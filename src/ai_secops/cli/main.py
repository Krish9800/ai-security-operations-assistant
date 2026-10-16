"""Typer CLI interface for AI Security Operations Assistant."""

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from ai_secops.config.settings import get_settings
from ai_secops.db.sqlite import DatabaseEngine
from ai_secops.guardrails.benchmark import AdversarialBenchmarkSuite
from ai_secops.guardrails.defense import SecOpsGuardrail
from ai_secops.hunter.planner import ThreatHuntingPlanner
from ai_secops.models.enums import MessageRole, SIEMTarget
from ai_secops.models.schemas import (
    QuerySynthesisRequest,
    SecurityAlert,
)
from ai_secops.narrative.generator import IncidentNarrativeGenerator
from ai_secops.recommender.engine import TriageRecommender
from ai_secops.synthesizer.engine import QuerySynthesizer

app = typer.Typer(
    name="ai-secops",
    help="Autonomous AI Security Operations Assistant (SecOps Copilot) CLI",
    add_completion=False,
)
console = Console()


@app.command()
def query(
    prompt: Annotated[str, typer.Argument(help="Natural language detection intent")],
    target: Annotated[
        SIEMTarget, typer.Option("--target", "-t", help="Target query format")
    ] = SIEMTarget.SPL,
    datasource: Annotated[
        str | None, typer.Option("--datasource", "-d", help="Custom index or sourcetype")
    ] = None,
) -> None:
    """Translate natural language security analyst prompt into validated SIEM query."""
    guardrail = SecOpsGuardrail()
    synthesizer = QuerySynthesizer()

    inspection = guardrail.inspect_prompt(prompt)
    if not inspection.is_safe:
        console.print(
            Panel(
                f"[bold red]Adversarial Prompt Injection Detected![/bold red]\n"
                f"Threats: {', '.join(inspection.detected_threats)}\n"
                f"Risk Score: {inspection.risk_score}",
                title="Security Guardrail Rejection",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    req = QuerySynthesisRequest(
        prompt=inspection.sanitized_input, target=target, data_source=datasource
    )
    res = synthesizer.synthesize(req)

    # Output formatted query
    lexer = (
        "yaml"
        if target == SIEMTarget.SIGMA
        else ("json" if target == SIEMTarget.ELASTICSEARCH else "sql")
    )
    syntax = Syntax(res.query, lexer, theme="monokai", line_numbers=True)

    console.print(
        Panel(
            syntax,
            title=f"Synthesized {target.value.upper()} Query (Validated: {res.validated})",
            border_style="green" if res.validated else "yellow",
        )
    )
    console.print(f"[bold cyan]Explanation:[/bold cyan] {res.explanation}")
    if res.syntax_notes:
        console.print(f"[dim yellow]Notes:[/dim yellow] {', '.join(res.syntax_notes)}")


@app.command()
def triage(
    alert_file: Annotated[
        Path, typer.Argument(help="Path to JSON file containing raw alerts list")
    ],
) -> None:
    """Ingest security alerts and produce confidence-calibrated containment recommendations."""
    if not alert_file.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {alert_file}")
        raise typer.Exit(code=1)

    try:
        raw_data = json.loads(alert_file.read_text())
        if isinstance(raw_data, dict):
            raw_data = [raw_data]
        alerts = [SecurityAlert.model_validate(item) for item in raw_data]
    except Exception as exc:
        console.print(f"[bold red]Failed to parse alerts:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    recommender = TriageRecommender()
    result = recommender.evaluate_triage(alerts)

    console.print(
        Panel(
            f"[bold]Incident ID:[/bold] {result.incident_id}\n"
            f"[bold]Severity:[/bold] {result.severity.value.upper()}\n"
            f"[bold]Overall Confidence:[/bold] {result.overall_confidence:.2f}\n"
            f"[bold]Risk Assessment:[/bold] {result.risk_assessment}",
            title="Triage Assessment Summary",
            border_style="cyan",
        )
    )

    table = Table(title="Recommended Containment Actions")
    table.add_column("Action ID", style="bold", no_wrap=True)
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Target Entity", style="magenta", no_wrap=True)
    table.add_column("Confidence", style="green")
    table.add_column("Blast Radius", style="yellow")
    table.add_column("Confirmation Req?", style="red")

    for act in result.recommended_actions:
        table.add_row(
            act.action_id,
            act.action_type.value,
            act.target_entity,
            f"{act.confidence_score:.2f} ({act.confidence_level.value})",
            f"{act.blast_radius_score:.2f}",
            "YES (Signoff Req)" if act.requires_confirmation else "No",
        )

    console.print(table)


@app.command()
def narrative(
    alert_file: Annotated[
        Path, typer.Argument(help="Path to JSON file containing alerts for narrative")
    ],
) -> None:
    """Generate forensic incident narrative, timeline, and Root Cause Analysis (RCA)."""
    if not alert_file.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {alert_file}")
        raise typer.Exit(code=1)

    try:
        raw_data = json.loads(alert_file.read_text())
        if isinstance(raw_data, dict):
            raw_data = [raw_data]
        alerts = [SecurityAlert.model_validate(item) for item in raw_data]
    except Exception as exc:
        console.print(f"[bold red]Failed to parse alerts:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    generator = IncidentNarrativeGenerator()
    narr = generator.generate_narrative(alerts)

    console.print(
        Panel(
            narr.executive_summary,
            title=f"Executive Brief ({narr.incident_id})",
            border_style="blue",
        )
    )
    console.print(
        Panel(
            narr.technical_narrative,
            title="Technical Findings & Root Cause",
            border_style="magenta",
        )
    )

    timeline_table = Table(title="Forensic Timeline")
    timeline_table.add_column("Timestamp", style="dim")
    timeline_table.add_column("Event Type", style="bold")
    timeline_table.add_column("Source", style="cyan")
    timeline_table.add_column("MITRE Technique", style="yellow")

    for evt in narr.timeline:
        timeline_table.add_row(
            evt.timestamp, evt.event_type, evt.source, evt.mitre_technique_id or "-"
        )

    console.print(timeline_table)


@app.command()
def hunt(
    query_str: Annotated[str, typer.Argument(help="MITRE ATT&CK technique ID or hunting theme")],
    playbook: Annotated[
        bool, typer.Option("--playbook", "-p", help="Generate full multi-hypothesis playbook")
    ] = False,
) -> None:
    """Generate proactive threat hunting hypotheses or playbooks mapped to MITRE ATT&CK."""
    planner = ThreatHuntingPlanner()

    if playbook:
        pb = planner.generate_playbook(query_str)
        console.print(Panel(pb.objective, title=pb.name, border_style="green"))
        console.print(f"[bold]Data Requirements:[/bold] {', '.join(pb.data_requirements)}\n")

        for h in pb.hypotheses:
            console.print(
                Panel(
                    f"[bold]Technique:[/bold] {h.technique_name} ({h.mitre_technique_id})\n"
                    f"[bold]Tactic:[/bold] {h.tactic.value}\n"
                    f"[bold]Hypothesis:[/bold] {h.hypothesis_statement}\n"
                    f"[bold]SPL Query:[/bold] {h.test_queries.get(SIEMTarget.SPL, 'N/A')}",
                    title=h.title,
                    border_style="cyan",
                )
            )
    else:
        hypo = planner.generate_hypothesis(query_str)
        console.print(
            Panel(
                f"[bold]Technique:[/bold] {hypo.technique_name} ({hypo.mitre_technique_id})\n"
                f"[bold]Tactic:[/bold] {hypo.tactic.value}\n"
                f"[bold]Hypothesis Statement:[/bold] {hypo.hypothesis_statement}",
                title=hypo.title,
                border_style="cyan",
            )
        )
        spl_q = hypo.test_queries.get(SIEMTarget.SPL, "")
        console.print(f"[bold cyan]SPL Detection Query:[/bold cyan]\n{spl_q}\n")
        console.print("[bold yellow]Inspection Checklist:[/bold yellow]")
        for item in hypo.inspection_checklist:
            console.print(f"  [green]•[/green] {item}")


@app.command()
def chat(
    session_id: Annotated[
        str | None, typer.Option("--session", "-s", help="Existing session ID to resume")
    ] = None,
) -> None:
    """Interactive SecOps Copilot terminal session."""
    settings = get_settings()
    db = DatabaseEngine(settings.resolve_db_path())
    guardrail = SecOpsGuardrail()
    synthesizer = QuerySynthesizer()

    active_sess_id = session_id
    if not active_sess_id or not db.get_session(active_sess_id):
        sess = db.create_session(title="Interactive CLI Session")
        active_sess_id = sess.session_id

    console.print(
        Panel(
            f"[bold green]SecOps Copilot Interactive Session Active[/bold green]\n"
            f"Session ID: [cyan]{active_sess_id}[/cyan]\n"
            f"Type your security question or 'exit' / 'quit' to end session.",
            title="SecOps Copilot",
            border_style="green",
        )
    )

    while True:
        try:
            user_input = typer.prompt("SecOps Analyst")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Session closed.[/dim]")
            break

        if user_input.strip().lower() in ("exit", "quit", "q"):
            console.print("[dim]Exiting Copilot session.[/dim]")
            break

        if not user_input.strip():
            continue

        inspection = guardrail.inspect_prompt(user_input)
        if not inspection.is_safe:
            console.print(
                f"[bold red]Guardrail Block:[/bold red] Adversarial attack detected: "
                f"{', '.join(inspection.detected_threats)}"
            )
            continue

        db.add_message(
            session_id=active_sess_id,
            role=MessageRole.USER,
            content=inspection.sanitized_input,
        )

        synth_res = synthesizer.synthesize(
            QuerySynthesisRequest(prompt=inspection.sanitized_input, target=SIEMTarget.SPL)
        )

        reply = (
            f"Synthesized query:\n```\n{synth_res.query}\n```\nAnalysis: {synth_res.explanation}"
        )

        db.add_message(
            session_id=active_sess_id,
            role=MessageRole.ASSISTANT,
            content=reply,
        )

        console.print(f"\n[bold green]Copilot:[/bold green]\n{reply}\n")


@app.command()
def benchmark() -> None:
    """Run adversarial prompt injection and guardrail benchmark evaluation."""
    suite = AdversarialBenchmarkSuite()
    report = suite.run()

    table = Table(title="SecOps Guardrail Adversarial Benchmark")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Total Test Cases", str(report.total_cases))
    table.add_row("Adversarial Attacks Evaluated", str(report.adversarial_cases))
    table.add_row("Benign Security Prompts", str(report.benign_cases))
    table.add_row("True Positives (Attacks Blocked)", str(report.true_positives))
    table.add_row("False Positives (Benign Flagged)", str(report.false_positives))
    table.add_row("Accuracy", f"{report.accuracy * 100:.1f}%")
    table.add_row("True Positive Rate (TPR)", f"{report.true_positive_rate * 100:.1f}%")
    table.add_row("False Positive Rate (FPR)", f"{report.false_positive_rate * 100:.1f}%")
    table.add_row("Avg Adversarial Risk Score", f"{report.avg_adversarial_risk:.2f}")
    table.add_row("Avg Benign Risk Score", f"{report.avg_benign_risk:.2f}")

    console.print(table)


@app.command()
def serve(
    host: Annotated[str, typer.Option("--host", "-h", help="Bind host address")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", "-p", help="Bind port")] = 8000,
    reload: Annotated[bool, typer.Option("--reload", help="Enable auto-reload")] = False,
) -> None:
    """Launch the FastAPI production server using Uvicorn."""
    import uvicorn

    console.print(f"[bold green]Starting SecOps API server on http://{host}:{port}[/bold green]")
    uvicorn.run("ai_secops.api.app:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    app()
