"""Run the fixture servers on loopback for demos and manual testing.

    uv run python scripts/demo_servers.py            # secure on :8401, misconfigured on :8402
    uv run mcp-posture scan http://127.0.0.1:8402/mcp --allow-private

Never point the scanner at servers you do not own; these local fixtures exist for that.
"""

from __future__ import annotations

import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.fixtures.servers import (
    McpProfile,
    counter_sessions,
    mcp_app,
    secure_as_metadata,
)


def profile(base: str, **changes: Any) -> McpProfile:
    prm = {
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
        "scopes_supported": ["mcp:tools"],
        "bearer_methods_supported": ["header"],
    }
    defaults: dict[str, Any] = {
        "prm": prm,
        "challenge": f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource/mcp"',
        "legacy_as_metadata": secure_as_metadata(base),
    }
    defaults.update(changes)
    return McpProfile(**defaults)


def misconfigured(base: str) -> McpProfile:
    meta = secure_as_metadata(base)
    meta.update(
        issuer=f"{base}/",
        code_challenge_methods_supported=["plain"],
        grant_types_supported=["authorization_code", "implicit", "password"],
        registration_endpoint=f"{base}/register",
    )
    meta.pop("client_id_metadata_document_supported")
    meta.pop("authorization_response_iss_parameter_supported")
    return profile(
        base,
        revision="2025-06-18",
        require_auth=False,
        sessions=counter_sessions(),
        prm={
            "resource": f"{base}/mcp/",
            "authorization_servers": [base],
            "bearer_methods_supported": ["header", "query"],
        },
        challenge="Bearer",
        legacy_as_metadata=meta,
        headers={"Server": "uvicorn/0.30.0"},
        not_found_body='Traceback (most recent call last):\n  File "/usr/src/app/main.py"',
    )


SERVERS: dict[int, tuple[str, Callable[[str], McpProfile]]] = {
    8401: ("secure", profile),
    8402: ("misconfigured", misconfigured),
}


def main() -> None:
    threads = []
    for port, (name, build) in SERVERS.items():
        base = f"http://127.0.0.1:{port}"
        app = mcp_app(build(base))
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        t = threading.Thread(target=uvicorn.Server(config).run, daemon=True)
        t.start()
        threads.append(t)
        print(f"{name:14} {base}/mcp")
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
