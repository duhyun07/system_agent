from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit
from core.policy import Policy
from security.permissions import PermissionDenied


class NetworkPolicy:
    def __init__(self, policy: Policy, resolver=None):
        self.policy = policy
        self.resolver = resolver

    def validate_url(self, url: str) -> tuple[str, str, int]:
        if any(ord(char) < 32 for char in url) or "\\" in url:
            raise PermissionDenied("Malformed URL")
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise PermissionDenied("Only credential-free HTTP/HTTPS URLs are allowed")
        host = parsed.hostname.rstrip(".").lower()
        if not self.policy.allowed_domains or not any(
            host == allowed.lower() or (allowed.startswith("*.") and host.endswith(allowed[1:].lower()) and host != allowed[2:].lower())
            for allowed in self.policy.allowed_domains
        ):
            raise PermissionDenied(f"Domain is not allowlisted: {host}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in (80, 443):
            raise PermissionDenied("Only standard HTTP/HTTPS ports are allowed")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise PermissionDenied("IP literal destinations are disabled")
        return parsed.scheme, host, port

    async def resolve_public(self, host: str, port: int) -> str:
        if self.resolver is not None:
            addresses = await self.resolver(host, port)
        else:
            records = await asyncio.to_thread(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM)
            addresses = [record[4][0] for record in records]
        if not addresses:
            raise PermissionDenied("DNS returned no addresses")
        parsed = [ipaddress.ip_address(address) for address in addresses]
        if not all(address.is_global for address in parsed):
            raise PermissionDenied("DNS resolved to a non-public address")
        return str(parsed[0])
