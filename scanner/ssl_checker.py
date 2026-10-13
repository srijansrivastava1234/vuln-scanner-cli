import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def _extract_issuer_name(cert: x509.Certificate) -> str:
    """Extracts Organization or Common Name from X.509 certificate issuer RDNs."""
    orgs = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    if orgs:
        return str(orgs[0].value)
    cns = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if cns:
        return str(cns[0].value)
    attrs = [attr.value for rdn in cert.issuer.rdns for attr in rdn]
    return str(attrs[-1]) if attrs else "Unknown"


def check_ssl(target: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Two-stage TLS probe:
    1. Strict handshake to verify chain validity.
    2. Fallback to unverified handshake upon SSLCertVerificationError to inspect
       actual certificate metadata (expiry date, issuer, reason) via cryptography.x509.
    """
    if "://" in target:
        parsed = urlparse(target)
        if parsed.scheme == "http":
            return {
                "status": "INSECURE_HTTP",
                "message": "Target specified plain HTTP scheme.",
                "days_remaining": 0,
                "expired": True,
            }
        hostname = parsed.hostname
        port = parsed.port or 443
    else:
        parts = target.split("/")[0].split(":")
        hostname = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 443

    if not hostname:
        return {"status": "ERROR", "message": "Invalid hostname provided."}

    # Stage 1: Verified handshake
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                now = datetime.now(timezone.utc)
                not_after = (
                    cert.not_valid_after_utc
                    if hasattr(cert, "not_valid_after_utc")
                    else cert.not_valid_after.replace(tzinfo=timezone.utc)
                )
                days_left = (not_after - now).days

                return {
                    "status": "VALID",
                    "tls_version": ssock.version(),
                    "cipher": ssock.cipher()[0],
                    "issuer": _extract_issuer_name(cert),
                    "expires_on": not_after.isoformat(),
                    "days_remaining": days_left,
                    "expired": False,
                }
    except ssl.SSLCertVerificationError as verify_err:
        # Stage 2: Handshake failed verification. Re-connect unverified to inspect peer cert
        unverified_context = ssl.create_default_context()
        unverified_context.check_hostname = False
        unverified_context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with unverified_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    now = datetime.now(timezone.utc)
                    not_after = (
                        cert.not_valid_after_utc
                        if hasattr(cert, "not_valid_after_utc")
                        else cert.not_valid_after.replace(tzinfo=timezone.utc)
                    )
                    days_left = (not_after - now).days
                    is_expired = days_left <= 0

                    return {
                        "status": "EXPIRED" if is_expired else "CERT_UNTRUSTED",
                        "error_detail": getattr(verify_err, "verify_message", str(verify_err)),
                        "tls_version": ssock.version(),
                        "issuer": _extract_issuer_name(cert),
                        "expires_on": not_after.isoformat(),
                        "days_remaining": days_left,
                        "expired": is_expired,
                    }
        except Exception as inner_err:
            return {
                "status": "CERT_UNTRUSTED",
                "error_detail": str(verify_err),
                "message": f"Could not inspect certificate: {inner_err}",
                "expired": True,
            }
    except (socket.gaierror, socket.timeout, ConnectionRefusedError, TimeoutError, OSError) as net_err:
        return {
            "status": "UNREACHABLE",
            "message": f"Connection failed: {net_err}",
            "expired": True,
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "message": str(e),
            "expired": True,
        }
