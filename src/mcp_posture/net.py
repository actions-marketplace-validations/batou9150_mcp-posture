"""Hardened HTTP layer.

* Every connection goes through :class:`GuardedBackend`, which resolves the host and refuses
  special-use addresses at connect time (no resolve-then-connect TOCTOU), unless private
  targets are explicitly allowed.
* Redirects are followed manually, one hop at a time, each hop re-guarded; credentials are
  never forwarded across origins.
* Bodies are streamed and capped; every request has a timeout; idempotent requests retry
  with exponential backoff.
* Every exchange is recorded as an immutable :class:`HttpExchange` for the checks to read.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import ssl
import time
import warnings
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx

from mcp_posture import __version__

DEFAULT_USER_AGENT = f"mcp-posture/{__version__} (+https://github.com/batou9150/mcp-posture)"
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
RETRY_STATUS = frozenset({429, 502, 503, 504})
IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS"})


class BlockedAddressError(httpx.ConnectError):
    """Raised when a host resolves to an address the scanner refuses to contact."""


# IPv6 ranges that carry an IPv4 address in their low 32 bits: NAT64 (RFC 6052, which Python
# treats as global), IPv4-compatible (deprecated) and SIIT IPv4-translated addresses.
_EMBEDDED_V4 = tuple(
    ipaddress.IPv6Network(n) for n in ("64:ff9b::/96", "64:ff9b:1::/48", "::/96", "::ffff:0:0:0/96")
)


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if any(ip in net for net in _EMBEDDED_V4):
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_special_use(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for loopback, private, link-local (incl. cloud metadata), CGNAT, multicast, reserved.

    IPv6 forms that embed an IPv4 address are judged by both the IPv6 and the IPv4 address.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        v4 = _embedded_ipv4(ip)
        if v4 is not None and is_special_use(v4):
            return True
    return not ip.is_global or ip.is_multicast


def host_is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def is_loopback_host(host: str) -> bool:
    h = host.strip("[]").lower()
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class NetSettings:
    timeout: float = 10.0
    max_bytes: int = 1_048_576
    retries: int = 2
    backoff: float = 0.5
    max_redirects: int = 5
    proxy: str | None = None
    ca_bundle: str | None = None
    user_agent: str = DEFAULT_USER_AGENT
    allow_private: bool = False


class GuardedBackend(httpcore.AsyncNetworkBackend):
    """Resolves, vets and connects to the vetted IP. TLS SNI still uses the original host."""

    def __init__(self, allow_private: bool, inner: httpcore.AsyncNetworkBackend | None = None):
        self._allow_private = allow_private
        self._inner = inner or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        last: Exception | None = None
        for ip in await resolve_vetted(host, port, self._allow_private):
            try:
                return await self._inner.connect_tcp(
                    ip,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as e:
                last = e
        raise httpcore.ConnectError(f"all connection attempts to {host} failed: {last}")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:  # pragma: no cover - never used
        raise BlockedAddressError("unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


async def resolve_vetted(host: str, port: int, allow_private: bool) -> list[str]:
    """Resolve ``host`` and return the addresses the policy allows, in resolver order.

    Disallowed addresses are never returned, so they can never be connected to.
    """
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host.strip("[]"), port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise httpx.ConnectError(f"cannot resolve {host}: {e}") from e
    allowed: list[str] = []
    blocked: list[str] = []
    for *_, sockaddr in infos:
        addr = str(sockaddr[0])
        if allow_private or not is_special_use(ipaddress.ip_address(addr)):
            if addr not in allowed:
                allowed.append(addr)
        else:
            blocked.append(addr)
    if allowed:
        return allowed
    raise BlockedAddressError(
        f"{host} resolves to special-use address(es) {', '.join(sorted(set(blocked)))}; "
        "pass --allow-private to scan private or loopback targets"
    )


class GuardedTransport(httpx.AsyncHTTPTransport):
    def __init__(self, settings: NetSettings, verify: ssl.SSLContext | bool) -> None:
        super().__init__(verify=verify, proxy=settings.proxy, trust_env=False, retries=0)
        if settings.proxy is None:
            # httpx does not expose ``network_backend``; swap the pool for one that uses the guard.
            ssl_context = verify if isinstance(verify, ssl.SSLContext) else None
            self._pool = httpcore.AsyncConnectionPool(
                ssl_context=ssl_context,
                network_backend=GuardedBackend(settings.allow_private),
            )


@dataclass(frozen=True)
class TlsInfo:
    version: str | None
    cipher: str | None
    not_after: str | None = None
    subject_cn: str | None = None


@dataclass(frozen=True)
class HttpExchange:
    method: str
    url: str
    request_headers: tuple[tuple[str, str], ...] = ()
    request_body: str | None = None
    status: int | None = None
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes = b""
    truncated: bool = False
    elapsed_ms: int = 0
    error: str | None = None
    blocked: bool = False
    tls: TlsInfo | None = None
    redirects: tuple[tuple[int, str], ...] = ()
    final_url: str = ""

    def header(self, name: str) -> str | None:
        name = name.lower()
        for k, v in self.headers:
            if k == name:
                return v
        return None

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k == name]

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").split(";")[0].strip().lower()

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        """Parsed JSON body, or ``None`` if the body is not JSON."""
        try:
            return json.loads(self.body)
        except (ValueError, UnicodeDecodeError, RecursionError):  # hostile nesting depth
            return None

    def describe(self) -> str:
        return f"{self.method} {self.url}"


def _origin(url: str) -> tuple[str, str, int | None]:
    p = urlsplit(url)
    return (p.scheme, (p.hostname or "").lower(), p.port)


def _tls_from(response: httpx.Response) -> TlsInfo | None:
    stream = response.extensions.get("network_stream")
    if stream is None:
        return None
    obj = stream.get_extra_info("ssl_object")
    if obj is None:
        return None
    cert = obj.getpeercert() or {}
    cn = None
    for rdn in cert.get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                cn = v
    cipher = obj.cipher()
    return TlsInfo(
        version=obj.version(),
        cipher=cipher[0] if cipher else None,
        not_after=cert.get("notAfter"),
        subject_cn=cn,
    )


def build_ssl_context(ca_bundle: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_bundle)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


StopFn = Callable[[bytes], bool]


class Fetcher:
    """Single entry point for network I/O during a scan. Records every exchange."""

    def __init__(
        self,
        settings: NetSettings,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.ssl_context = build_ssl_context(settings.ca_bundle)
        self._transport = transport or GuardedTransport(settings, self.ssl_context)
        self._client = httpx.AsyncClient(
            transport=self._transport,
            timeout=httpx.Timeout(settings.timeout),
            follow_redirects=False,
            headers={"User-Agent": settings.user_agent},
            trust_env=False,
        )
        self.log: list[HttpExchange] = []

    async def __aenter__(self) -> Fetcher:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        json_body: Any = None,
        follow_redirects: bool = True,
        max_bytes: int | None = None,
        stop_when: StopFn | None = None,
        read_timeout: float | None = None,
        record: bool = True,
    ) -> HttpExchange:
        hops: list[tuple[int, str]] = []
        current_url = url
        current_method = method.upper()
        body = json_body
        hdrs = dict(headers or {})
        start_origin = _origin(url)
        exchange: HttpExchange | None = None
        for _ in range(self.settings.max_redirects + 1):
            exchange = await self._send_with_retries(
                current_method, current_url, hdrs, body, max_bytes, stop_when, read_timeout
            )
            location = exchange.header("location")
            if not (follow_redirects and exchange.status in REDIRECT_CODES and location):
                break
            hops.append((exchange.status or 0, location))
            next_url = urljoin(current_url, location)
            if urlsplit(next_url).scheme not in ("http", "https"):
                break
            if exchange.status == 303 or (
                exchange.status in (301, 302) and current_method not in IDEMPOTENT
            ):
                current_method, body = "GET", None
            if _origin(next_url) != start_origin:
                hdrs = {
                    k: v for k, v in hdrs.items() if k.lower() not in ("authorization", "cookie")
                }
            current_url = next_url
        if exchange is None:  # pragma: no cover - the loop runs at least once
            raise RuntimeError("no exchange")
        result = replace(
            exchange,
            method=method.upper(),
            url=url,
            redirects=tuple(hops),
            final_url=exchange.url,
        )
        if record:
            self.log.append(result)
        return result

    async def _send_with_retries(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        json_body: Any,
        max_bytes: int | None,
        stop_when: StopFn | None,
        read_timeout: float | None,
    ) -> HttpExchange:
        attempts = 1 + (self.settings.retries if method in IDEMPOTENT else 0)
        last: HttpExchange | None = None
        for attempt in range(attempts):
            last = await self._send_once(
                method, url, headers, json_body, max_bytes, stop_when, read_timeout
            )
            retryable = (last.error is not None and not last.blocked) or (
                last.status in RETRY_STATUS
            )
            if not retryable or attempt == attempts - 1:
                break
            delay = self.settings.backoff * (2**attempt)
            retry_after = last.header("retry-after")
            if retry_after and retry_after.isdigit():
                delay = min(float(retry_after), 10.0)
            await asyncio.sleep(delay)
        if last is None:  # pragma: no cover - the loop runs at least once
            raise RuntimeError("no exchange")
        return last

    async def _send_once(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        json_body: Any,
        max_bytes: int | None,
        stop_when: StopFn | None,
        read_timeout: float | None,
    ) -> HttpExchange:
        limit = max_bytes or self.settings.max_bytes
        content = None if json_body is None else json.dumps(json_body).encode()
        req_headers = dict(headers)
        if content is not None:
            req_headers.setdefault("Content-Type", "application/json")
        started = time.monotonic()
        req_tuple = tuple((k.lower(), v) for k, v in req_headers.items())
        req_body = content.decode() if content is not None else None
        if self.settings.proxy is not None and not self.settings.allow_private:
            # The proxy connects for us, so the connect-time guard never sees the target: vet
            # the host here, on every request and redirect hop. The proxy may still resolve
            # the name differently (documented in the threat model).
            parts = urlsplit(url)
            port = parts.port or (443 if parts.scheme == "https" else 80)
            try:
                await resolve_vetted(parts.hostname or "", port, allow_private=False)
            except BlockedAddressError as e:
                return HttpExchange(
                    method, url, req_tuple, req_body, error=str(e), blocked=True, final_url=url
                )
            except httpx.ConnectError as e:
                return HttpExchange(
                    method, url, req_tuple, req_body, error=_describe_error(e), final_url=url
                )
        try:
            request = self._client.build_request(method, url, headers=req_headers, content=content)
            # Straight to the transport: httpx's client parses Location even when not following
            # redirects and raises on malformed values, which a hostile server could exploit.
            # One deadline for connect + status line + headers: httpx's own timeouts apply per
            # read and restart with every byte, so a server trickling headers would never time out.
            async with asyncio.timeout(self.settings.timeout):
                response = await self._transport.handle_async_request(request)
            response.request = request
        except TimeoutError:
            return HttpExchange(
                method,
                url,
                req_tuple,
                req_body,
                error=f"TimeoutError: no response headers within {self.settings.timeout:g}s",
                final_url=url,
            )
        except BlockedAddressError as e:
            return HttpExchange(
                method, url, req_tuple, req_body, error=str(e), blocked=True, final_url=url
            )
        except (httpx.HTTPError, httpx.InvalidURL, ssl.SSLError, OSError) as e:
            return HttpExchange(
                method, url, req_tuple, req_body, error=_describe_error(e), final_url=url
            )
        try:
            tls = _tls_from(response)
            buf = bytearray()
            truncated = False
            try:
                async with asyncio.timeout(read_timeout or self.settings.timeout):
                    async for chunk in response.aiter_bytes():
                        buf.extend(chunk)
                        if len(buf) > limit:
                            del buf[limit:]
                            truncated = True
                            break
                        # Stop conditions look for complete lines; skip chunks without one.
                        if stop_when is not None and b"\n" in chunk and stop_when(bytes(buf)):
                            break
            except TimeoutError:
                truncated = True
            except httpx.HTTPError as e:
                return HttpExchange(
                    method,
                    url,
                    req_tuple,
                    req_body,
                    status=response.status_code,
                    headers=tuple((k.lower(), v) for k, v in response.headers.multi_items()),
                    body=bytes(buf),
                    error=_describe_error(e),
                    tls=tls,
                    final_url=url,
                )
        finally:
            await response.aclose()
        return HttpExchange(
            method=method,
            url=url,
            request_headers=req_tuple,
            request_body=req_body,
            status=response.status_code,
            headers=tuple((k.lower(), v) for k, v in response.headers.multi_items()),
            body=bytes(buf),
            truncated=truncated,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            tls=tls,
            final_url=url,
        )


def _describe_error(e: BaseException) -> str:
    text = str(e) or type(e).__name__
    cause = e.__cause__ or e.__context__
    if isinstance(cause, ssl.SSLCertVerificationError):
        text = f"TLS certificate verification failed: {cause.verify_message}"
    elif isinstance(cause, ssl.SSLError):
        text = f"TLS error: {cause.reason or cause}"
    return f"{type(e).__name__}: {text}"


@dataclass(frozen=True)
class TlsProbe:
    host: str
    port: int
    verified: bool
    error: str | None = None
    version: str | None = None
    not_after: str | None = None
    legacy_accepted: bool | None = None
    legacy_version: str | None = None
    details: dict[str, str] = field(default_factory=dict)


async def probe_tls(
    host: str, port: int, *, ca_bundle: str | None, allow_private: bool, timeout: float = 10.0
) -> TlsProbe:
    """Handshake once with full verification, once offering only TLS 1.0/1.1."""
    try:
        ips = await resolve_vetted(host, port, allow_private)
    except httpx.ConnectError as e:
        return TlsProbe(host, port, verified=False, error=str(e))
    ip = await _first_reachable(ips, port, timeout)
    if ip is None:
        return TlsProbe(host, port, verified=False, error="TCP connection failed")
    verified, error, version, not_after = False, None, None, None
    ctx = ssl.create_default_context(cafile=ca_bundle)
    try:
        async with asyncio.timeout(timeout):
            _, writer = await asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host)
        obj = writer.get_extra_info("ssl_object")
        version = obj.version() if obj else None
        not_after = (obj.getpeercert() or {}).get("notAfter") if obj else None
        verified = True
        writer.close()
    except ssl.SSLCertVerificationError as e:
        error = f"certificate verification failed: {e.verify_message}"
    except (ssl.SSLError, OSError, TimeoutError) as e:
        error = f"TLS handshake failed: {type(e).__name__}: {e}"
    legacy_accepted, legacy_version = await _probe_legacy_tls(ip, port, host, timeout)
    return TlsProbe(
        host,
        port,
        verified=verified,
        error=error,
        version=version,
        not_after=not_after,
        legacy_accepted=legacy_accepted,
        legacy_version=legacy_version,
    )


async def _first_reachable(ips: list[str], port: int, timeout: float) -> str | None:
    for ip in ips:
        try:
            async with asyncio.timeout(timeout):
                _, writer = await asyncio.open_connection(ip, port)
        except (OSError, TimeoutError):
            continue
        writer.close()
        return ip
    return None


async def _probe_legacy_tls(
    ip: str, port: int, host: str, timeout: float
) -> tuple[bool | None, str | None]:
    """Offer only TLS 1.0/1.1. ``None`` means the local OpenSSL cannot test it."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # we only test protocol acceptance, never send data
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)  # deprecated on purpose
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ssl.SSLError, ValueError):
        return None, None
    try:
        async with asyncio.timeout(timeout):
            _, writer = await asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host)
    except ssl.SSLError as e:
        reason = (e.reason or "").upper()
        if "NO_PROTOCOLS_AVAILABLE" in reason or "NO_SUPPORTED_VERSIONS_ENABLED" in reason:
            return None, None
        return False, None
    except (OSError, TimeoutError):
        return False, None
    obj = writer.get_extra_info("ssl_object")
    version = obj.version() if obj else None
    writer.close()
    return True, version
