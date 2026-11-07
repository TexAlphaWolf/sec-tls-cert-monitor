"""The documentation must not drift away from the code."""

import re
from pathlib import Path

import pytest

from tlswatch import cli, report
from tlswatch.checks import CIPHER_FINDINGS
from tlswatch.probe import CIPHER_CLASSES

ROOT = Path(__file__).resolve().parent.parent
MARKDOWN = [ROOT / n for n in ("README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md")]
MARKDOWN += sorted((ROOT / "docs").glob("*.md"))


def read(*parts):
    return ROOT.joinpath(*parts).read_text(encoding="utf-8")


def finding_ids():
    """Every finding id that appears in the source of checks.py."""
    source = read("src", "tlswatch", "checks.py")
    found = set(re.findall(r'Finding\(\s*"([\w-]+)"', source))
    return found | {f"cipher-{name}" for name in CIPHER_FINDINGS}


def test_every_finding_is_in_the_grading_table():
    text = read("docs", "grading.md")
    missing = sorted(i for i in finding_ids() if f"`{i}`" not in text)
    assert missing == []


def test_the_grading_table_lists_no_finding_that_does_not_exist():
    table = [line for line in read("docs", "grading.md").splitlines() if line.startswith("| `")]
    documented = set(re.findall(r"`([a-z0-9-]+)`", " ".join(row.split("|")[1] for row in table)))
    assert documented <= finding_ids()


def test_every_prometheus_metric_is_documented_and_used_names_exist():
    sample = report.prometheus([])
    assert sample == "\n"
    source = read("src", "tlswatch", "report.py")
    metrics = set(re.findall(r'"(tlswatch_\w+)"', source))
    doc = read("docs", "prometheus.md")
    assert sorted(m for m in metrics if f"`{m}`" not in doc) == []
    alerts = set(re.findall(r"tlswatch_\w+", read("examples", "prometheus-alerts.yml")))
    assert sorted(alerts - metrics) == []


def test_every_cipher_class_is_probed_and_documented():
    text = read("docs", "grading.md")
    for name, _ in CIPHER_CLASSES:
        assert f"cipher-{name}" in text


def test_readme_documents_every_command_line_option():
    text = read("README.md")
    parser = cli.build_parser()
    for sub in parser._subparsers._group_actions[0].choices.values():  # type: ignore[union-attr]
        for action in sub._actions:
            for option in action.option_strings:
                if option.startswith("--") and option not in ("--help", "--version"):
                    assert option in text, option


def test_example_configuration_loads():
    from tlswatch.config import load

    settings = load(ROOT / "examples" / "tlswatch.toml")
    assert len(settings.targets) == 3 and settings.min_grade == "B"
    assert settings.targets[1].starttls == "smtp"


@pytest.mark.parametrize("path", MARKDOWN, ids=lambda p: p.name)
def test_relative_links_point_at_files_that_exist(path):
    for target in re.findall(r"\]\(([^)\s]+)\)", path.read_text(encoding="utf-8")):
        if target.startswith(("http://", "https://", "#", "mailto:")):
            continue
        assert (path.parent / target.split("#", 1)[0]).exists(), (
            f"{path.name}: broken link {target}"
        )


def test_workflows_referenced_by_the_readme_exist():
    for name in re.findall(r"actions/workflows/([\w.-]+\.yml)", read("README.md")):
        assert (ROOT / ".github" / "workflows" / name).exists(), name


def test_the_screenshot_exists():
    assert (ROOT / "docs" / "demo.png").stat().st_size > 10_000
