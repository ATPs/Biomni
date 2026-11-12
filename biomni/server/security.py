"""System identity, exact ingress CIDRs, and safe provider destinations."""

import grp
import ipaddress
import os
import pwd
import socket
from urllib.parse import urlsplit, urlunsplit

PRIVATE_CIDRS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


class AccessDenied(PermissionError):
    pass


def system_user(username):
    if not isinstance(username, str) or not username or len(username) > 128:
        raise AccessDenied("Invalid system user")
    try:
        return pwd.getpwnam(username)
    except KeyError as exc:
        raise AccessDenied("Unknown system user") from exc


def is_admin(username):
    user = system_user(username)
    try:
        return grp.getgrnam("wheel").gr_gid in os.getgrouplist(username, user.pw_gid)
    except KeyError:
        return False


def allowed_client(address, cidrs=PRIVATE_CIDRS):
    try:
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return isinstance(ip, ipaddress.IPv4Address) and any(
            ip in ipaddress.ip_network(network, strict=True) for network in cidrs
        )
    except ValueError:
        return False


def provider_url(value, *, forbidden_hosts=(), forbidden_ports=(), resolve=True):
    """Keep private API providers valid; exclude app/control and metadata targets."""
    if not isinstance(value, str) or any(ord(c) < 33 for c in value):
        raise ValueError("Provider URL must be HTTP or HTTPS")
    url = urlsplit(value)
    if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password:
        raise ValueError("Provider URL must not contain credentials")
    if url.query or url.fragment:
        raise ValueError("Provider base URL must not have a query or fragment")
    port = url.port or (443 if url.scheme == "https" else 80)
    blocked = set(forbidden_hosts) | {"localhost", "metadata.google.internal"}
    if url.hostname.lower() in blocked:
        raise ValueError("Provider points to an internal service")
    if port in set(forbidden_ports):
        raise ValueError("Provider points to a protected service port")
    addresses = []
    if resolve:
        try:
            addresses = [item[4][0] for item in socket.getaddrinfo(url.hostname, port, type=socket.SOCK_STREAM)]
        except socket.gaierror as exc:
            raise ValueError("Provider hostname cannot be resolved") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            raise ValueError("Provider address is not allowed")
        if str(ip) in blocked:
            raise ValueError("Provider points to an internal service")
    return urlunsplit((url.scheme, url.netloc, url.path.rstrip("/"), "", ""))
