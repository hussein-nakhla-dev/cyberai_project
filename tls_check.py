"""TLS inspection pinned to the IP we already validated."""
from __future__ import annotations

import socket
import ssl
from datetime import timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from ..config import TLS_TIMEOUT
from ..models import Observation
from ..rules import make_finding
from ..utils import clean, now_utc
from .base import CheckOutput, ScanContext


def _handshake(ip: str, port: int, host: str, verify: bool) -> dict:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, port), timeout=TLS_TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cipher = tls.cipher()
            return {
                "der": tls.getpeercert(binary_form=True),
                "version": tls.version() or "?",
                "cipher": cipher[0] if cipher else "?",
            }


def _name(cert_name: x509.Name) -> str:
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        attrs = cert_name.get_attributes_for_oid(oid)
        if attrs:
            return clean(attrs[0].value, 80)
    return "?"


def check_tls(ctx: ScanContext) -> CheckOutput:
    t, out = ctx.target, CheckOutput()
    port = t.port if (t.scheme == "https" and t.port) else 443
    ip = t.ips[0]

    verify_error = None
    try:
        info = _handshake(ip, port, t.host, verify=True)
    except ssl.SSLCertVerificationError as exc:
        verify_error = clean(getattr(exc, "verify_message", "") or str(exc), 160)
        info = _handshake(ip, port, t.host, verify=False)

    cert = x509.load_der_x509_certificate(info["der"])
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    days_left = (not_after - now_utc()).days

    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_desc, key_bits = f"RSA-{public_key.key_size}", public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_desc, key_bits = f"EC-{public_key.curve.name}", 256
    else:
        key_desc, key_bits = type(public_key).__name__, 0

    out.observations += [
        Observation("tls_version", info["version"]),
        Observation("tls_cipher", info["cipher"]),
        Observation("cert_subject", _name(cert.subject)),
        Observation("cert_issuer", _name(cert.issuer)),
        Observation("cert_expiry", f"{not_after:%Y-%m-%d} ({days_left}d)"),
        Observation("cert_key", key_desc),
    ]

    if verify_error:
        out.findings.append(make_finding(
            "TLS-INVALID", t.host, "TLS-Inspector",
            {"reason": verify_error, "days_remaining": days_left},
            confidence=1.0, key="invalid", timestamp=ctx.timestamp,
        ))
    elif days_left < 20:
        out.findings.append(make_finding(
            "TLS-EXPIRING", t.host, "TLS-Inspector", {"days_remaining": days_left},
            confidence=1.0, key="expiring", timestamp=ctx.timestamp,
        ))
    if info["version"] in ("SSLv3", "TLSv1", "TLSv1.1"):
        out.findings.append(make_finding(
            "TLS-LEGACY", t.host, "TLS-Inspector", {"version": info["version"]},
            confidence=1.0, key="legacy", timestamp=ctx.timestamp,
        ))
    if isinstance(public_key, rsa.RSAPublicKey) and key_bits < 2048:
        out.findings.append(make_finding(
            "TLS-WEAKKEY", t.host, "TLS-Inspector", {"key": key_desc},
            confidence=1.0, key="weakkey", timestamp=ctx.timestamp,
        ))
    return out
