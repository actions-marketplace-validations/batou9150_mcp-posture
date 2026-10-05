"""Golden-file tests for renderers, and drift test for the published JSON schema.

Regenerate goldens with ``UPDATE_GOLDEN=1 uv run pytest tests/test_report.py``.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path

import jsonschema

from mcp_posture.models import (
    Confidence,
    Evidence,
    Finding,
    Report,
    Severity,
    SpecRevision,
    TargetResult,
    ToolInfo,
)
from mcp_posture.redact import Redactor
from mcp_posture.report import render
from mcp_posture.report.json import json_schema
from tests.conftest import run_scan
from tests.fixtures.servers import AsProfile, McpProfile, secure_as_metadata

ROOT = Path(__file__).parent.parent
GOLDEN = Path(__file__).parent / "golden"
SCHEMA_PATH = ROOT / "docs" / "schema" / "report-v1.json"
UPDATE = os.environ.get("UPDATE_GOLDEN") == "1"
WHEN = datetime(2026, 1, 1, tzinfo=UTC)


def sample_report() -> Report:
    meta = secure_as_metadata()
    meta["code_challenge_methods_supported"] = ["S256", "plain"]
    meta.pop("authorization_response_iss_parameter_supported")
    result = run_scan(
        McpProfile(challenge=None, headers={"Server": "nginx/1.25.3"}), AsProfile(metadata=meta)
    )
    return Report(
        tool=ToolInfo(version="0.0.0-test"),
        generated_at=WHEN,
        mode="passive",
        fail_on=Severity.HIGH,
        targets=(result,),
    )


def check_golden(name: str, text: str) -> None:
    path = GOLDEN / name
    if UPDATE:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert text == path.read_text(encoding="utf-8"), f"{name} drifted; set UPDATE_GOLDEN=1"


def test_json_golden_and_schema_valid() -> None:
    text = render(sample_report(), "json", Redactor())
    check_golden("report.json", text)
    jsonschema.validate(json.loads(text), json_schema())


def test_table_golden() -> None:
    check_golden("report.txt", render(sample_report(), "table", Redactor()))


def test_table_unreachable_and_clean_targets() -> None:
    clean = run_scan(McpProfile(), AsProfile(), disable=frozenset({"ASM", "CIMD"}))
    down = clean.model_copy(
        update={"target": "https://down.test", "reachable": False, "error": "x"}
    )
    report = Report(
        tool=ToolInfo(version="t"),
        generated_at=None,
        mode="passive",
        fail_on=Severity.HIGH,
        targets=(clean, down),
    )
    text = render(report, "table", Redactor(), color=True)
    assert "no findings" in text and "unreachable: x" in text


def test_render_redacts() -> None:
    report = sample_report()
    secret = report.targets[0].findings[0].message.split()[0]
    assert secret not in render(report, "json", Redactor([secret]))


def test_published_schema_matches_models() -> None:
    generated = json.dumps(json_schema(), indent=2, sort_keys=True) + "\n"
    if UPDATE:
        SCHEMA_PATH.parent.mkdir(parents=True, exist_ok=True)
        SCHEMA_PATH.write_text(generated, encoding="utf-8")
    assert SCHEMA_PATH.read_text(encoding="utf-8") == generated, "run with UPDATE_GOLDEN=1"


SARIF_SCHEMA = json.loads(
    (Path(__file__).parent / "schemas" / "sarif-schema-2.1.0.json").read_text()
)


def suppressed_report() -> Report:
    from mcp_posture.suppress import parse_suppressions

    report = sample_report()
    target = report.targets[0]
    rules = parse_suppressions(
        '[[ignore]]\ncheck = "TRN05"\njustification = "HSTS is set by the CDN in front"\n'
    )
    from mcp_posture.suppress import apply_suppressions

    findings = tuple(apply_suppressions(target.findings, rules, WHEN.date()))
    return report.model_copy(
        update={"targets": (target.model_copy(update={"findings": findings}),)}
    )


def test_sarif_golden_and_schema_valid() -> None:
    from mcp_posture.report import sarif

    report = suppressed_report()
    text = render(
        report, "sarif", Redactor(), anchors={report.targets[0].target: ("targets.txt", 3)}
    )
    check_golden("report.sarif", text)
    doc = json.loads(text)
    jsonschema.validate(doc, SARIF_SCHEMA)
    run = doc["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert "MCPP-ERR00" in rule_ids and len(rule_ids) == len(set(rule_ids))
    for result in run["results"]:
        assert rule_ids[result["ruleIndex"]] == result["ruleId"]
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "targets.txt" and loc["region"]["startLine"] == 3
        assert result["partialFingerprints"]["primaryLocationLineHash"]
    assert sum(1 for r in run["results"] if r.get("suppressions")) == 1
    default = json.loads(sarif.render(report))
    assert (
        default["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
            "uri"
        ]
        == "mcp-posture.toml"
    )


def test_sarif_unreachable_notification() -> None:
    from mcp_posture.models import TargetResult

    down = TargetResult(
        target="https://down.test",
        reachable=False,
        error="refused",
        spec_revision=SpecRevision.R2026_07_28,
        revision_source="default",
    )
    report = Report(
        tool=ToolInfo(version="t"),
        generated_at=None,
        mode="passive",
        fail_on=Severity.HIGH,
        targets=(down,),
    )
    doc = json.loads(render(report, "sarif", Redactor()))
    jsonschema.validate(doc, SARIF_SCHEMA)
    inv = doc["runs"][0]["invocations"][0]
    assert (
        not inv["executionSuccessful"]
        and "refused" in inv["toolExecutionNotifications"][0]["message"]["text"]
    )


def test_markdown_golden() -> None:
    text = render(suppressed_report(), "markdown", Redactor())
    check_golden("report.md", text)
    assert "1 suppressed finding(s)" in text and "HSTS is set by the CDN" in text


def test_markdown_rug_pull_details_and_unreachable() -> None:
    pin = Finding(
        check_id="MCPP-PIN03",
        title="changed",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        target="https://a.test",
        location="tool:x",
        message="tool:x changed | description.",
        evidence=(Evidence(summary="diff", excerpt="-old\n+new"),),
    )
    ok = TargetResult(
        target="https://a.test",
        name="prod",
        reachable=True,
        spec_revision=SpecRevision.R2026_07_28,
        revision_source="default",
        findings=(pin,),
    )
    down = ok.model_copy(
        update={"target": "https://b.test", "reachable": False, "error": "x", "findings": ()}
    )
    report = Report(
        tool=ToolInfo(version="t"),
        generated_at=None,
        mode="passive",
        fail_on=Severity.HIGH,
        targets=(ok, down),
    )
    text = render(report, "markdown", Redactor())
    assert "```diff\n-old\n+new\n```" in text and "changed \\| description" in text
    assert "Unreachable: ` x `" in text and "(` prod `)" in text and text.startswith("## ❌")


def test_markdown_neutralizes_server_controlled_markup() -> None:
    """Tool names and messages reach PR comments: no images, links, mentions or fence breaks."""
    from mcp_posture.context import SurfaceItem, freeze
    from mcp_posture.pin import unified_diff

    hostile = "x\n```\n![p](https://attacker.example/p.png) @org/team <img src=x>"
    diff = unified_diff({"description": "a"}, {"description": "b ```` c"}, f"tool:{hostile}")
    pin = Finding(
        check_id="MCPP-PIN03",
        title="Tool definition changed since pin (rug pull)",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        target="https://a.test",
        location=f"tool:{hostile}",
        message=f"tool:{hostile} changed `quoted`.",
        evidence=(Evidence(summary="diff", excerpt=diff),),
    )
    item = SurfaceItem(kind="tool", name=hostile, definition=freeze({"name": hostile}))
    assert item.location.startswith("tool:x")
    result = TargetResult(
        target="https://a.test",
        reachable=True,
        spec_revision=SpecRevision.R2026_07_28,
        revision_source="default",
        findings=(pin,),
    )
    report = Report(
        tool=ToolInfo(version="t"),
        generated_at=None,
        mode="passive",
        fail_on=Severity.HIGH,
        targets=(result,),
    )
    text = render(report, "markdown", Redactor())
    # The diff block opens with a fence longer than any backtick run inside, and closes it.
    assert "`````diff\n" in text and "\n`````\n" in text
    # Outside code (spans and blocks), no markup from the server survives.
    prose = re.sub(r"(`{3,})diff\n.*?\n\1\n", "", text, flags=re.S)
    prose = re.sub(r"(`+) .*? \1", "", prose)
    prose = re.sub(r"<code>.*?</code>", "", prose)
    assert "\n\n" not in text.split("<summary>")[1].split("</summary>")[0]
    assert "![p]" not in prose and "@org" not in prose and "<img" not in prose
    assert "&lt;img src=x&gt;" in text  # HTML-escaped inside <summary>


def test_reports_never_emit_raw_control_or_invisible_characters() -> None:
    """Hostile servers control tool names and error bodies: no terminal escape injection."""
    import unicodedata

    from tests.fixtures.servers import POISONED_TOOLS, McpProfile

    nasty = {**POISONED_TOOLS[1], "name": "evil\x1b[2J" + chr(0x202E) + "tool"}
    result = run_scan(
        McpProfile(require_auth=False, tools=[*POISONED_TOOLS, nasty], unauth_body="\x1b]0;pwn\x07")
    )
    report = Report(
        tool=ToolInfo(version="t"),
        generated_at=None,
        mode="passive",
        fail_on=Severity.HIGH,
        targets=(result,),
    )
    for fmt in ("table", "json", "sarif", "markdown"):
        text = render(report, fmt, Redactor())
        bad = {c for c in text if unicodedata.category(c) in ("Cf", "Co", "Cc") and c not in "\n\t"}
        assert not bad, (fmt, bad)
        if fmt in ("json", "sarif"):
            assert "\\u202e" in text  # escaped, still inspectable
    colored = render(report, "table", Redactor(), color=True)
    assert "\x1b[" in colored and "\x1b[2J" not in colored and "<U+001B>[2J" in colored
