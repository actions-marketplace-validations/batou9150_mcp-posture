"""JSON report (schema version 1.0, published in docs/schema/report-v1.json)."""

from __future__ import annotations

import json
from typing import Any

from mcp_posture.models import Report


def to_dict(report: Report) -> dict[str, Any]:
    return report.model_dump(mode="json")


def render(report: Report) -> str:
    return json.dumps(to_dict(report), indent=2, ensure_ascii=False) + "\n"


def json_schema() -> dict[str, Any]:
    schema = Report.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "https://batou9150.github.io/mcp-posture/schema/report-v1.json"
    schema["title"] = "mcp-posture report"
    return schema
