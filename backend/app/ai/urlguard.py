"""Base-URL validation for admin-configured LLM endpoints (SSRF guard).

Rejects non-HTTP schemes, embedded credentials, query strings, cloud metadata hosts and link-local addresses, and can
pin hosts with AEGIS_LLM_ALLOWED_HOSTS. Loopback and private addresses stay allowed for self-hosted models. Hostnames
are not resolved here (DNS answers can change); use the allowlist to pin hosts in hardened deployments.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 500
METADATA_HOSTS = frozenset(
    {"metadata", "metadata.google.internal", "metadata.goog", "instance-data", "instance-data.ec2.internal"}
)
_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in ("169.254.0.0/16", "fe80::/10", "fd00:ec2::254/128", "100.100.100.200/32")
)


class UrlRejected(ValueError):
    pass


def validate_base_url(url: str, allowed_hosts: Iterable[str] = ()) -> str:
    candidate = url.strip()
    if not candidate or len(candidate) > MAX_URL_LENGTH:
        raise UrlRejected(f"Base URL must be 1-{MAX_URL_LENGTH} characters")
    parts = urlsplit(candidate)
    if parts.scheme not in ("http", "https"):
        raise UrlRejected("Base URL must use http or https")
    if parts.username or parts.password or "@" in parts.netloc:
        raise UrlRejected("Base URL must not contain credentials; use the API key field")
    if parts.query or parts.fragment:
        raise UrlRejected("Base URL must not contain a query string or fragment")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise UrlRejected("Base URL must include a host")
    if host in METADATA_HOSTS:
        raise UrlRejected("Cloud metadata endpoints are not allowed")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and (
        address.is_multicast
        or address.is_unspecified
        or any(address.version == net.version and address in net for net in _BLOCKED_NETWORKS)
    ):
        raise UrlRejected("Link-local, metadata and unspecified addresses are not allowed")
    allowed = {h.lower() for h in allowed_hosts}
    if allowed and host not in allowed:
        raise UrlRejected("This host is not in AEGIS_LLM_ALLOWED_HOSTS")
    try:
        port = parts.port
    except ValueError:
        raise UrlRejected("Base URL has an invalid port") from None
    netloc = f"[{host}]" if address is not None and address.version == 6 else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    return urlunsplit((parts.scheme, netloc, parts.path.rstrip("/"), "", ""))
