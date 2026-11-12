"""Compatible API transport; keys never enter scientific worker processes."""

import ipaddress
import json

from tornado.httpclient import HTTPRequest
from tornado.netutil import DefaultExecutorResolver
from tornado.simple_httpclient import SimpleAsyncHTTPClient

from .security import provider_url


def valid_key(value):
    return isinstance(value, str) and len(value) <= 4096 and all(32 < ord(c) < 127 for c in value)


class SafeResolver(DefaultExecutorResolver):
    async def resolve(self, host, port, family=0):
        result = await super().resolve(host, port, family)
        for _, address in result:
            ip = ipaddress.ip_address(address[0])  # address is a sockaddr tuple
            if getattr(ip, "ipv4_mapped", None):
                ip = ip.ipv4_mapped
            if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
                raise ValueError("Provider resolved to a protected address")
        return result


class ProviderTransport:
    def __init__(self, *, forbidden_hosts=(), forbidden_ports=(8765,), timeout=600):
        self.forbidden_hosts = tuple(forbidden_hosts)
        self.forbidden_ports = tuple(forbidden_ports)
        self.timeout = timeout
        self.client = SimpleAsyncHTTPClient(
            force_instance=True, resolver=SafeResolver(), max_body_size=32 * 1024 * 1024
        )

    def normalize(self, url, *, resolve=True):
        """Validate a provider base URL. Resolution blocks: call from a worker thread."""
        return provider_url(
            url, forbidden_hosts=self.forbidden_hosts, forbidden_ports=self.forbidden_ports, resolve=resolve
        )

    async def fetch(self, settings, path, body=None, *, stream=None):
        # No blocking DNS here: SafeResolver re-checks every address at connect time.
        base = self.normalize(settings["url"], resolve=False)
        if path not in {"models", "chat/completions", "responses"}:
            raise ValueError("Unsupported provider API path")
        headers = {"Accept": "application/json"}
        if not valid_key(settings.get("api_key") or ""):
            raise ValueError("Stored API key contains invalid characters")
        if settings.get("api_key"):
            headers["Authorization"] = "Bearer " + settings["api_key"]
        if body is not None:
            headers["Content-Type"] = "application/json"
        status = [0]

        def header(line):
            if line.startswith("HTTP/"):
                status[0] = int(line.split()[1])

        def chunk(value):
            if 200 <= status[0] < 300:
                stream(value)

        request = HTTPRequest(
            base + "/" + path,
            method="GET" if body is None else "POST",
            headers=headers,
            body=None if body is None else json.dumps(body).encode(),
            connect_timeout=10,
            request_timeout=self.timeout,
            follow_redirects=False,
            streaming_callback=chunk if stream else None,
            header_callback=header if stream else None,
            validate_cert=True,
        )
        return await self.client.fetch(request, raise_error=False)

    async def discover(self, settings):
        response = await self.fetch(settings, "models")
        if response.code != 200:
            raise ValueError(f"Model discovery failed (HTTP {response.code}); manual IDs remain available")
        try:
            payload = json.loads(response.body)
            records = payload["data"]
            models = sorted(
                {
                    item["id"]
                    for item in records
                    if isinstance(item, dict) and isinstance(item.get("id"), str) and 0 < len(item["id"]) <= 512
                }
            )
        except (TypeError, KeyError, ValueError) as exc:
            raise ValueError("Provider returned an invalid models response") from exc
        return models

    def close(self):
        self.client.close()
