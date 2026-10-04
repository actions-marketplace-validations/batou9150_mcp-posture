"""Golden-file tests for renderers, and drift test for the published JSON schema.

Regenerate goldens with ``UPDATE_GOLDEN=1 uv run pytest tests/test_report.py``.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import jsonschema

from mcp_posture.models import Report, Severity, ToolInfo
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
