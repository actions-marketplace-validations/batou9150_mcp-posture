from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import AsyncIterator

import httpx
import pytest

from mcp_posture.net import (
    BlockedAddressError,
    Fetcher,
    GuardedBackend,
    HttpExchange,
    NetSettings,
    host_is_ip_literal,
    is_loopback_host,
    is_special_use,
    resolve_vetted,
)


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.5.4",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",  # noqa: S104 - an address under test, not a bind
        "::1",
        "fe80::1",
        "fd00::1",
        "::ffff:127.0.0.1",
        "224.0.0.1",
    ],
)
def test_special_use_addresses(ip: str) -> None:
    assert is_special_use(ipaddress.ip_address(ip))


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses(ip: str) -> None:
    assert not is_special_use(ipaddress.ip_address(ip))


def test_host_helpers() -> None:
    assert host_is_ip_literal("[::1]") and not host_is_ip_literal("example.com")
    assert is_loopback_host("localhost") and is_loopback_host("app.localhost")
    assert is_loopback_host("127.0.0.2") and not is_loopback_host("example.com")


def test_resolve_vetted_blocks_loopback() -> None:
    with pytest.raises(BlockedAddressError, match="--allow-private"):
        asyncio.run(resolve_vetted("localhost", 80, allow_private=False))
    assert asyncio.run(resolve_vetted("127.0.0.1", 80, allow_private=True)) == ["127.0.0.1"]


def test_resolve_unknown_host() -> None:
    with pytest.raises(httpx.ConnectError, match="cannot resolve"):
        asyncio.run(resolve_vetted("nonexistent.invalid", 80, allow_private=False))


def test_guarded_backend_refuses_before_connecting() -> None:
    backend = GuardedBackend(allow_private=False)
    with pytest.raises(BlockedAddressError):
        asyncio.run(backend.connect_tcp("127.0.0.1", 1))


def test_real_fetch_to_loopback_is_blocked() -> None:
    async def go() -> HttpExchange:
        async with Fetcher(NetSettings(retries=0)) as f:
            return await f.request("GET", "http://127.0.0.1:9/")

    ex = asyncio.run(go())
    assert ex.blocked and ex.status is None and "special-use" in (ex.error or "")


def _fetch(handler: httpx.MockTransport, *args: object, **kwargs: object) -> HttpExchange:
    async def go() -> HttpExchange:
        settings = NetSettings(retries=2, backoff=0, max_bytes=kwargs.pop("max_bytes", 1024))  # type: ignore[arg-type]
        async with Fetcher(settings, transport=handler) as f:
            return await f.request(*args, **kwargs)  # type: ignore[arg-type]

    return asyncio.run(go())


def test_redirects_are_followed_and_recorded_and_auth_stripped_cross_origin() -> None:
    seen: list[tuple[str, str | None]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.headers.get("authorization")))
        if request.url.host == "a.test" and request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "/same"})
        if request.url.path == "/same":
            return httpx.Response(307, headers={"Location": "https://b.test/final"})
        return httpx.Response(200, json={"ok": True})

    ex = _fetch(
        httpx.MockTransport(handle),
        "GET",
        "https://a.test/start",
        headers={"Authorization": "Bearer t"},
    )
    assert ex.status == 200 and ex.json() == {"ok": True}
    assert ex.redirects == ((302, "/same"), (307, "https://b.test/final"))
    assert ex.final_url == "https://b.test/final" and ex.url == "https://a.test/start"
    assert seen == [
        ("https://a.test/start", "Bearer t"),
        ("https://a.test/same", "Bearer t"),
        ("https://b.test/final", None),
    ]


def test_redirect_loop_is_bounded_and_post_becomes_get_on_303() -> None:
    methods: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        return httpx.Response(303, headers={"Location": "/again"})

    ex = _fetch(httpx.MockTransport(handle), "POST", "https://a.test/", json_body={"x": 1})
    assert ex.status == 303 and len(ex.redirects) == 6
    assert methods[0] == "POST" and set(methods[1:]) == {"GET"}


def test_no_follow_and_non_http_location() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "javascript:alert(1)"})

    assert _fetch(httpx.MockTransport(handle), "GET", "https://a.test/").redirects == (
        (302, "javascript:alert(1)"),
    )
    nofollow = _fetch(httpx.MockTransport(handle), "GET", "https://a.test/", follow_redirects=False)
    assert nofollow.redirects == () and nofollow.status == 302


def test_body_is_capped() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 5000)

    ex = _fetch(httpx.MockTransport(handle), "GET", "https://a.test/", max_bytes=100)
    assert ex.truncated and len(ex.body) == 100 and ex.json() is None


def test_retries_on_503_then_success() -> None:
    calls = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) < 3:
            return httpx.Response(503, headers={"Retry-After": "0"})
        return httpx.Response(200, text="ok")

    ex = _fetch(httpx.MockTransport(handle), "GET", "https://a.test/")
    assert ex.status == 200 and len(calls) == 3


def test_post_is_not_retried_and_errors_are_recorded() -> None:
    calls = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        raise httpx.ConnectError("boom", request=request)

    ex = _fetch(httpx.MockTransport(handle), "POST", "https://a.test/", json_body={})
    assert ex.status is None and "boom" in (ex.error or "") and len(calls) == 1
    get = _fetch(httpx.MockTransport(handle), "GET", "https://a.test/")
    assert get.error and len(calls) == 4


def test_stop_when_ends_streaming_early() -> None:
    async def chunks() -> AsyncIterator[bytes]:
        yield b"event: endpoint\ndata: /messages\n\n"
        await asyncio.sleep(30)
        yield b"never"

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=chunks(), headers={"content-type": "text/event-stream"})

    ex = _fetch(
        httpx.MockTransport(handle),
        "GET",
        "https://a.test/sse",
        stop_when=lambda b: b"endpoint" in b,
    )
    assert ex.text.startswith("event: endpoint") and not ex.truncated


def test_read_timeout_marks_truncated() -> None:
    async def chunks() -> AsyncIterator[bytes]:
        yield b"data: partial\n"
        await asyncio.sleep(30)

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=chunks())

    ex = _fetch(httpx.MockTransport(handle), "GET", "https://a.test/", read_timeout=0.05)
    assert ex.truncated and ex.text == "data: partial\n"


def test_exchange_helpers() -> None:
    ex = HttpExchange(
        "GET",
        "https://a/",
        status=200,
        headers=(("content-type", "Application/JSON; charset=utf-8"), ("x", "1"), ("x", "2")),
        body=b'{"a": 1}',
    )
    assert ex.content_type == "application/json" and ex.ok
    assert ex.header("X") == "1" and ex.header_all("x") == ["1", "2"] and ex.header("y") is None
    assert ex.describe() == "GET https://a/"
