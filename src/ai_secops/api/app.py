"""FastAPI control plane for SecOps Copilot API."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ai_secops.config.settings import Settings, get_settings
from ai_secops.db.sqlite import DatabaseEngine
from ai_secops.guardrails.defense import SecOpsGuardrail
from ai_secops.hunter.planner import ThreatHuntingPlanner
from ai_secops.models.enums import ActionStatus, MessageRole, SIEMTarget
from ai_secops.models.schemas import (
    HuntingPlaybook,
    IncidentNarrative,
    QuerySynthesisRequest,
    QuerySynthesisResponse,
    RecommendationResult,
    SecurityAlert,
    ThreatHuntingHypothesis,
)
from ai_secops.narrative.generator import IncidentNarrativeGenerator
from ai_secops.recommender.engine import TriageRecommender
from ai_secops.synthesizer.engine import QuerySynthesizer


# Request models for API
class ChatRequest(BaseModel):
    """Chat input message from an analyst."""

    prompt: str = Field(
        ..., min_length=1, max_length=4096, description="Analyst query or instruction"
    )
    session_id: str | None = Field(default=None, description="Optional conversation session ID")


class ChatResponse(BaseModel):
    """Response returned by SecOps copilot."""

    session_id: str
    reply: str
    synthesized_query: str | None = None
    target_siem: SIEMTarget | None = None
    detected_threats: list[str] = Field(default_factory=list)


class HuntRequest(BaseModel):
    """Request to generate hunting hypothesis."""

    query: str = Field(..., min_length=2, description="Technique ID or hunting topic")


class PlaybookRequest(BaseModel):
    """Request to generate hunting playbook."""

    tactic: str = Field(..., min_length=2, description="ATT&CK tactic or theme")


class ActionStatusUpdateRequest(BaseModel):
    """Request to update containment action status."""

    status: ActionStatus = Field(..., description="Target action status")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure FastAPI application."""
    app_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        # Startup: initialize database and singletons
        db = DatabaseEngine(app_settings.resolve_db_path())
        app.state.db = db
        app.state.guardrail = SecOpsGuardrail()
        app.state.synthesizer = QuerySynthesizer()
        app.state.narrative_gen = IncidentNarrativeGenerator()
        app.state.recommender = TriageRecommender()
        app.state.hunter = ThreatHuntingPlanner()
        yield

    app = FastAPI(
        title=app_settings.app_name,
        version=app_settings.app_version,
        description="Autonomous AI Security Operations Assistant (SecOps Copilot) API",
        lifespan=lifespan,
    )

    # Middleware: CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=app_settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Security Headers Middleware
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        return response

    # --- Routes ---

    @app.get("/health", tags=["System"])
    async def health_check() -> dict[str, str]:
        """Health check probe endpoint."""
        return {
            "status": "healthy",
            "app_name": app_settings.app_name,
            "version": app_settings.app_version,
            "environment": app_settings.environment,
        }

    @app.post("/api/v1/copilot/chat", response_model=ChatResponse, tags=["Copilot"])
    async def copilot_chat(req: ChatRequest) -> ChatResponse:
        """Process analyst chat, check guardrails, synthesize queries, and persist session."""
        guardrail: SecOpsGuardrail = app.state.guardrail
        db: DatabaseEngine = app.state.db
        synthesizer: QuerySynthesizer = app.state.synthesizer

        # 1. Inspect input through guardrail
        inspection = guardrail.inspect_prompt(req.prompt)
        if not inspection.is_safe:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Adversarial prompt injection or prohibited input detected",
                    "threats": inspection.detected_threats,
                    "risk_score": inspection.risk_score,
                },
            )

        # 2. Manage session
        session_id = req.session_id
        if not session_id or not db.get_session(session_id):
            sess = db.create_session(title=req.prompt[:50])
            session_id = sess.session_id

        # 3. Add user message
        db.add_message(
            session_id=session_id,
            role=MessageRole.USER,
            content=inspection.sanitized_input,
            metadata={"risk_score": inspection.risk_score},
        )

        # 4. Generate response / synthesized query if applicable
        synth_req = QuerySynthesisRequest(prompt=inspection.sanitized_input, target=SIEMTarget.SPL)
        synth_res = synthesizer.synthesize(synth_req)

        # Log query to audit db
        db.log_query(
            prompt=inspection.sanitized_input,
            target=synth_res.target,
            query=synth_res.query,
            validated=synth_res.validated,
            explanation=synth_res.explanation,
            session_id=session_id,
        )

        reply_content = (
            f"Here is your analyzed detection query:\n\n```spl\n{synth_res.query}\n```\n\n"
            f"**Analysis**: {synth_res.explanation}"
        )

        # Add assistant message
        db.add_message(
            session_id=session_id,
            role=MessageRole.ASSISTANT,
            content=reply_content,
            metadata={"synthesized_query": synth_res.query, "target": synth_res.target.value},
        )

        return ChatResponse(
            session_id=session_id,
            reply=reply_content,
            synthesized_query=synth_res.query,
            target_siem=synth_res.target,
            detected_threats=[],
        )

    @app.post(
        "/api/v1/synthesizer/generate",
        response_model=QuerySynthesisResponse,
        tags=["Synthesizer"],
    )
    async def generate_query(req: QuerySynthesisRequest) -> QuerySynthesisResponse:
        """Translate natural language query into validated SIEM / Sigma query."""
        guardrail: SecOpsGuardrail = app.state.guardrail
        db: DatabaseEngine = app.state.db
        synthesizer: QuerySynthesizer = app.state.synthesizer

        inspection = guardrail.inspect_prompt(req.prompt)
        if not inspection.is_safe:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Input rejected by guardrail",
                    "threats": inspection.detected_threats,
                },
            )

        resp = synthesizer.synthesize(
            QuerySynthesisRequest(
                prompt=inspection.sanitized_input,
                target=req.target,
                timeframe=req.timeframe,
                data_source=req.data_source,
            )
        )

        db.log_query(
            prompt=inspection.sanitized_input,
            target=resp.target,
            query=resp.query,
            validated=resp.validated,
            explanation=resp.explanation,
        )

        return resp

    @app.post(
        "/api/v1/narrative/generate",
        response_model=IncidentNarrative,
        tags=["Narrative"],
    )
    async def generate_narrative(alerts: list[SecurityAlert]) -> IncidentNarrative:
        """Ingest security alerts and construct a forensic narrative and RCA."""
        if not alerts:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="At least one alert is required.",
            )

        narrative_gen: IncidentNarrativeGenerator = app.state.narrative_gen
        db: DatabaseEngine = app.state.db

        try:
            narrative = narrative_gen.generate_narrative(alerts)
            db.save_incident_narrative(narrative)
            return narrative
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    @app.post(
        "/api/v1/recommender/triage",
        response_model=RecommendationResult,
        tags=["Recommender"],
    )
    async def triage_incident(alerts: list[SecurityAlert]) -> RecommendationResult:
        """Run confidence-calibrated triage and containment recommendation."""
        if not alerts:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="At least one alert is required.",
            )

        recommender: TriageRecommender = app.state.recommender
        db: DatabaseEngine = app.state.db

        try:
            result = recommender.evaluate_triage(alerts)
            db.save_recommendations(result.incident_id, result.recommended_actions)
            return result
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    @app.patch(
        "/api/v1/recommendations/{action_id}/status",
        tags=["Recommender"],
    )
    async def update_action_status(
        action_id: str, req: ActionStatusUpdateRequest
    ) -> dict[str, Any]:
        """Update containment action execution status."""
        db: DatabaseEngine = app.state.db
        updated = db.update_action_status(action_id, req.status)
        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Action '{action_id}' not found.",
            )
        return {"action_id": action_id, "status": req.status.value, "updated": True}

    @app.post(
        "/api/v1/hunter/hypothesize",
        response_model=ThreatHuntingHypothesis,
        tags=["Hunter"],
    )
    async def hunt_hypothesis(req: HuntRequest) -> ThreatHuntingHypothesis:
        """Generate threat hunting hypothesis mapped to MITRE ATT&CK."""
        hunter: ThreatHuntingPlanner = app.state.hunter
        return hunter.generate_hypothesis(req.query)

    @app.post(
        "/api/v1/hunter/playbook",
        response_model=HuntingPlaybook,
        tags=["Hunter"],
    )
    async def hunt_playbook(req: PlaybookRequest) -> HuntingPlaybook:
        """Generate structured hunting playbook by ATT&CK tactic."""
        hunter: ThreatHuntingPlanner = app.state.hunter
        return hunter.generate_playbook(req.tactic)

    @app.get("/api/v1/sessions", tags=["Sessions"])
    async def list_sessions() -> list[dict[str, Any]]:
        """List active conversation sessions."""
        db: DatabaseEngine = app.state.db
        return db.list_sessions()

    @app.get("/api/v1/sessions/{session_id}", tags=["Sessions"])
    async def get_session(session_id: str) -> dict[str, Any]:
        """Get session message history."""
        db: DatabaseEngine = app.state.db
        session = db.get_session(session_id)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session '{session_id}' not found.",
            )
        return session.model_dump()

    @app.delete("/api/v1/sessions/{session_id}", tags=["Sessions"])
    async def delete_session(session_id: str) -> dict[str, bool]:
        """Delete session and cascade message logs."""
        db: DatabaseEngine = app.state.db
        deleted = db.delete_session(session_id)
        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session '{session_id}' not found.",
            )
        return {"deleted": True}

    return app


app = create_app()
