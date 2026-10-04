"""SARIF 2.1.0 output, shaped for GitHub code scanning.

Code scanning only displays results attached to a file in the repository, so every result
is anchored to the file its target came from (targets file, config file, ``.mcp.json``),
on the line that contains the URL, or to a fallback anchor (``--sarif-anchor``).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from mcp_posture.models import CheckMeta, Finding, Report, Severity
from mcp_posture.registry import ERROR_CHECK_ID, catalogue

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
DOCS = "https://batou9150.github.io/mcp-posture/checks"
FINGERPRINT_KEY = "mcpPosture/v1"

LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.5",
}

Anchor = tuple[str, int]
DEFAULT_ANCHOR: Anchor = ("mcp-posture.toml", 1)


def _rule(meta: CheckMeta) -> dict[str, Any]:
    refs = "\n".join(f"- [{r.title}]({r.url})" for r in meta.references)
    return {
        "id": meta.id,
        "name": "".join(
            w.capitalize() for w in meta.title.replace("-", " ").split() if w.isalnum()
        ),
        "shortDescription": {"text": meta.title},
        "fullDescription": {"text": meta.rationale},
        "helpUri": f"{DOCS}/{meta.docs_slug}/",
        "help": {
            "text": f"{meta.rationale}\n\nRemediation: {meta.remediation}",
            "markdown": f"{meta.rationale}\n\n**Remediation:** {meta.remediation}\n\n{refs}",
        },
        "defaultConfiguration": {"level": LEVEL[meta.severity]},
        "properties": {
            "tags": ["security", "mcp", meta.family.lower()],
            "precision": {"high": "high", "medium": "medium", "low": "low"}[meta.confidence.value],
            "security-severity": SECURITY_SEVERITY[meta.severity],
            "mcp-spec-revisions": [r.value for r in meta.revisions],
        },
    }


_ERROR_RULE: dict[str, Any] = {
    "id": ERROR_CHECK_ID,
    "name": "CheckError",
    "shortDescription": {"text": "Check failed to run"},
    "fullDescription": {"text": "A check raised an internal error; its result is unknown."},
    "help": {"text": "Re-run with --verbose and report the error to the mcp-posture maintainers."},
    "defaultConfiguration": {"level": "note"},
    "properties": {"tags": ["mcp-posture"], "security-severity": "0.5"},
}


def _result(
    f: Finding, rule_index: Mapping[str, int], anchor: Anchor, target_name: str | None
) -> dict[str, Any]:
    text = f"{f.message} [{f.target}]"
    evidence = [e.summary + (f": {e.excerpt}" if e.excerpt else "") for e in f.evidence]
    result: dict[str, Any] = {
        "ruleId": f.check_id,
        "ruleIndex": rule_index[f.check_id],
        "level": LEVEL[f.severity],
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": anchor[0]},
                    "region": {"startLine": anchor[1], "startColumn": 1},
                },
                "logicalLocations": [
                    {"fullyQualifiedName": f"{f.target}#{f.location}", "kind": "resource"}
                ],
            }
        ],
        "partialFingerprints": {
            FINGERPRINT_KEY: f.fingerprint,
            "primaryLocationLineHash": f.fingerprint,
        },
        "properties": {
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "target": f.target,
            "location": f.location,
            **({"targetName": target_name} if target_name else {}),
            **({"evidence": evidence} if evidence else {}),
        },
    }
    if f.suppression is not None and not f.suppression.expired:
        result["suppressions"] = [
            {"kind": "external", "status": "accepted", "justification": f.suppression.justification}
        ]
    return result


def to_dict(
    report: Report,
    anchors: Mapping[str, Anchor] | None = None,
    default_anchor: Anchor = DEFAULT_ANCHOR,
) -> dict[str, Any]:
    rules = [_rule(m) for m in catalogue()] + [_ERROR_RULE]
    index = {r["id"]: i for i, r in enumerate(rules)}
    anchors = anchors or {}
    results = [
        _result(f, index, anchors.get(t.target, default_anchor), t.name)
        for t in report.targets
        for f in t.findings
    ]
    notifications = [
        {
            "level": "error",
            "message": {"text": f"{t.target} unreachable: {t.error}"},
            "descriptor": {"id": "target-unreachable"},
        }
        for t in report.targets
        if not t.reachable
    ]
    invocation: dict[str, Any] = {
        "executionSuccessful": not notifications,
        "toolExecutionNotifications": notifications,
    }
    if report.generated_at is not None:
        invocation["endTimeUtc"] = report.generated_at.isoformat().replace("+00:00", "Z")
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.tool.name,
                        "version": report.tool.version,
                        "semanticVersion": report.tool.version,
                        "informationUri": report.tool.information_uri,
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": "mcp-posture/"},
                "invocations": [invocation],
                "results": results,
                "properties": {"mode": report.mode, "failOn": report.fail_on.value},
            }
        ],
    }


def render(
    report: Report,
    anchors: Mapping[str, Anchor] | None = None,
    default_anchor: Anchor = DEFAULT_ANCHOR,
) -> str:
    return json.dumps(to_dict(report, anchors, default_anchor), indent=2, ensure_ascii=False) + "\n"
