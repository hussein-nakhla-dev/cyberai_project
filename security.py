"""Target validation and SSRF-hardened HTTP access."""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import requests
import urllib3

from .config import ALLOWED_WEB_PORTS, HTTP_TIMEOUT, MAX_REDIRECTS, USER_AGENT
from .models import Target

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63})$")
HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
REDIRECT_CODES = {301, 302, 303, 307, 308}


class TargetError(Exception):
    """Raised with a short machine code (maps to err.<code> in i18n)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return bool(
        ip.is_global
        and not (ip.is_multicast or ip.is_reserved or ip.is_unspecified
                 or ip.is_loopback or ip.is_link_local)
    )


def resolve_public(host: str) -> list[str]:
    """Resolve host; every returned address must be public or we refuse."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise TargetError("unresolvable")
    ips = list(dict.fromkeys(i[4][0].split("%")[0] for i in infos))
    if not ips:
        raise TargetError("unresolvable")
    if not all(is_public_ip(ip) for ip in ips):
        raise TargetError("restricted")
    return ips


def parse_target(raw: str) -> Target:
    text = (raw or "").strip()
    if not text:
        raise TargetError("empty")
    if len(text) > 2048 or any(c.isspace() for c in text):
        raise TargetError("invalid")

    match = EMAIL_RE.match(text)
    if match:
        return Target(raw=text, kind="email", host=match.group(1).lower(), email=text.lower())

    def ip_target(value: str) -> Target:
        if not is_public_ip(value):
            raise TargetError("restricted")
        return Target(raw=text, kind="ip", host=value, ips=(value,))

    try:
        return ip_target(str(ipaddress.ip_address(text.strip("[]"))))
    except ValueError:
        pass

    parts = urlsplit(text if "://" in text else "https://" + text)
    if parts.scheme not in ("http", "https"):
        raise TargetError("invalid")
    if parts.username or parts.password:
        raise TargetError("credentials")
    try:
        explicit_port = parts.port
    except ValueError:
        raise TargetError("invalid")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise TargetError("invalid")

    try:
        return ip_target(str(ipaddress.ip_address(host)))
    except ValueError:
        pass

    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise TargetError("invalid")
    if "." not in host or not HOST_RE.match(host):
        raise TargetError("invalid")

    default = 443 if parts.scheme == "https" else 80
    port = explicit_port or default
    if port not in ALLOWED_WEB_PORTS:
        raise TargetError("port")

    ips = resolve_public(host)
    return Target(
        raw=text,
        kind="url",
        host=host,
        scheme=parts.scheme,
        port=explicit_port if explicit_port and explicit_port != default else None,
        path=parts.path or "/",
        ips=tuple(ips),
    )


@dataclass
class HttpResult:
    status: int
    url: str
    headers: "requests.structures.CaseInsensitiveDict"
    set_cookies: list[str] = field(default_factory=list)
    body: bytes = b""
    chain: list[str] = field(default_factory=list)


def safe_request(
    url: str,
    *,
    method: str = "GET",
    follow: bool = True,
    max_bytes: int = 0,
    timeout: float = HTTP_TIMEOUT,
    verify: bool = True,
) -> HttpResult:
    """HTTP request that re-validates scheme, port and DNS on every hop.

    Residual risk: DNS can change between our check and the connection
    (rebinding). Run the app in a network segment with no internal reachability.
    """
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session = requests.Session()
    session.trust_env = False  # ignore proxy environment variables
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    chain: list[str] = []
    current = url

    for _ in range(MAX_REDIRECTS + 1):
        parts = urlsplit(current)
        if parts.scheme not in ("http", "https") or parts.username or parts.password:
            raise TargetError("invalid")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if port not in ALLOWED_WEB_PORTS:
            raise TargetError("port")
        resolve_public(parts.hostname or "")
        chain.append(current)

        resp = session.request(
            method, current, headers=headers, timeout=timeout,
            allow_redirects=False, stream=True, verify=verify,
        )
        location = resp.headers.get("Location")
        if follow and resp.status_code in REDIRECT_CODES and location:
            resp.close()
            current = urljoin(current, location)
            continue

        body = resp.raw.read(max_bytes, decode_content=True) if max_bytes else b""
        raw_headers = getattr(resp.raw, "headers", None)
        cookies = list(raw_headers.getlist("Set-Cookie")) if raw_headers is not None else []
        result = HttpResult(resp.status_code, current, resp.headers, cookies, body, chain)
        resp.close()
        return result

    raise requests.exceptions.TooManyRedirects("redirect limit exceeded")
