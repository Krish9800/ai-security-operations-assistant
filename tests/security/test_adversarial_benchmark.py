"""Tests for AdversarialBenchmarkSuite and CLI benchmark command."""

from typer.testing import CliRunner

from ai_secops.cli.main import app
from ai_secops.guardrails.benchmark import AdversarialBenchmarkSuite


def test_adversarial_benchmark_suite_metrics() -> None:
    """Verify that AdversarialBenchmarkSuite correctly evaluates prompt injection resistance."""
    suite = AdversarialBenchmarkSuite()
    report = suite.run()

    # Accuracy must be 100% on the default benchmark set
    assert report.total_cases >= 10
    assert report.adversarial_cases >= 5
    assert report.benign_cases >= 5
    assert report.true_positives == report.adversarial_cases
    assert report.false_positives == 0
    assert report.accuracy == 1.0
    assert report.true_positive_rate == 1.0
    assert report.false_positive_rate == 0.0
    assert report.avg_adversarial_risk > 0.50
    assert report.avg_benign_risk == 0.0


def test_cli_benchmark_command() -> None:
    """Verify CLI benchmark command execution and output formatting."""
    runner = CliRunner()
    res = runner.invoke(app, ["benchmark"])
    assert res.exit_code == 0
    assert "SecOps Guardrail Adversarial Benchmark" in res.output
    assert "True Positives" in res.output
    assert "Accuracy" in res.output
