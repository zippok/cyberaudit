"""
CyberAudit Target Verifier & Anti-SSRF Defense Guardrail
Validates external targets (domains, IPs, URLs) to prevent:
1. Server-Side Request Forgery (SSRF) against internal network infrastructure and cloud metadata.
2. Unauthorized scanning against third-party assets without verified domain ownership.
"""

import socket
import ipaddress
import urllib.parse
from typing import List, Tuple, Optional
import urllib.request
import ssl


class TargetVerificationError(Exception):
    """Base exception for target validation failures."""
    pass


class SSRFBlockedError(TargetVerificationError):
    """Raised when an IP or domain resolves to a forbidden/private network segment."""
    pass


class OwnershipVerificationError(TargetVerificationError):
    """Raised when target domain ownership cannot be confirmed via challenge file or DNS TXT."""
    pass


class TargetVerifier:
    """Enterprise defensive guardrail to validate scan targets before any network activity."""

    # Disallowed IP networks (RFC 1918, link-local, cloud metadata, loopback, multicast)
    FORBIDDEN_NETWORKS = [
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),          # RFC 1918 Private
        ipaddress.ip_network("100.64.0.0/10"),       # Shared Address Space / CGNAT
        ipaddress.ip_network("127.0.0.0/8"),         # Loopback
        ipaddress.ip_network("169.254.0.0/16"),      # Link-local / Cloud Metadata (AWS/GCP/Azure)
        ipaddress.ip_network("172.16.0.0/12"),       # RFC 1918 Private
        ipaddress.ip_network("192.0.0.0/24"),        # IETF Protocol Assignments
        ipaddress.ip_network("192.0.2.0/24"),        # Documentation (TEST-NET-1)
        ipaddress.ip_network("192.168.0.0/16"),      # RFC 1918 Private
        ipaddress.ip_network("198.18.0.0/15"),       # Benchmarking
        ipaddress.ip_network("198.51.100.0/24"),     # Documentation (TEST-NET-2)
        ipaddress.ip_network("203.0.113.0/24"),      # Documentation (TEST-NET-3)
        ipaddress.ip_network("224.0.0.0/4"),         # Multicast
        ipaddress.ip_network("240.0.0.0/4"),         # Reserved
        ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
        # IPv6
        ipaddress.ip_network("::/128"),              # Unspecified
        ipaddress.ip_network("::1/128"),             # Loopback
        ipaddress.ip_network("fc00::/7"),            # Unique Local (ULA)
        ipaddress.ip_network("fe80::/10"),           # Link-Local Unicast
        ipaddress.ip_network("ff00::/8"),            # Multicast
    ]

    CHALLENGE_WELL_KNOWN_PATH = "/.well-known/cyberaudit-challenge.txt"
    DNS_VERIFY_PREFIX = "_cyberaudit-verify"

    @classmethod
    def extract_host(cls, target: str) -> Tuple[str, Optional[int]]:
        """
        Extracts clean hostname and optional port from a URL, hostname, or IP string.
        """
        target = target.strip()
        if not target:
            raise TargetVerificationError("El objetivo no puede estar vacío.")

        if "://" in target:
            parsed = urllib.parse.urlparse(target)
            hostname = parsed.hostname
            port = parsed.port
            if not hostname:
                raise TargetVerificationError(f"No se pudo extraer el host de la URL: {target}")
            return hostname, port

        # Check for host:port without scheme
        if ":" in target and not target.startswith("["):
            parts = target.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                return parts[0], int(parts[1])

        return target, None

    @classmethod
    def resolve_target_ips(cls, host: str) -> List[str]:
        """
        Resolves host to all associated IP addresses (IPv4 and IPv6).
        """
        try:
            addr_info = socket.getaddrinfo(host, None)
            ips = list({res[4][0] for res in addr_info})
            if not ips:
                raise TargetVerificationError(f"No se obtuvieron registros DNS IP para {host}")
            return ips
        except socket.gaierror as e:
            raise TargetVerificationError(f"Error en resolución DNS de '{host}': {e}")

    @classmethod
    def validate_safe_target(
        cls,
        target: str,
        allow_local: bool = False,
    ) -> Tuple[str, List[str]]:
        """
        Performs strict Anti-SSRF inspection.
        Returns tuple of (hostname, resolved_ips).
        Raises SSRFBlockedError if any resolved IP falls in a forbidden/internal range.
        """
        host, _ = cls.extract_host(target)

        # Handle direct IP input or domain resolution
        try:
            ip_direct = ipaddress.ip_address(host)
            resolved_ips = [str(ip_direct)]
        except ValueError:
            resolved_ips = cls.resolve_target_ips(host)

        if allow_local:
            return host, resolved_ips

        for ip_str in resolved_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                raise TargetVerificationError(f"IP inválida resuelta: {ip_str}")

            for forbidden_net in cls.FORBIDDEN_NETWORKS:
                if ip_obj in forbidden_net:
                    raise SSRFBlockedError(
                        f"Target bloqueado por política Anti-SSRF de CyberAudit: "
                        f"'{host}' resolvió a la dirección restringida {ip_str} "
                        f"perteneciente a la red {forbidden_net}. "
                        f"(Usa --allow-local exclusivamente en entornos de desarrollo aislados)."
                    )

        return host, resolved_ips

    @classmethod
    def verify_domain_ownership(
        cls,
        target: str,
        expected_token: str,
        method: str = "auto",
        timeout: float = 5.0,
    ) -> bool:
        """
        Verifies domain ownership before conducting active scans.
        Method: 'challenge_file', 'dns_txt', or 'auto' (tries challenge_file, then dns_txt).
        """
        host, _ = cls.extract_host(target)
        expected_token = expected_token.strip()
        if not expected_token:
            raise OwnershipVerificationError("El token de verificación no puede estar vacío.")

        # 1. Challenge file check: https://<host>/.well-known/cyberaudit-challenge.txt
        if method in ("challenge_file", "auto"):
            for scheme in ("https", "http"):
                challenge_url = f"{scheme}://{host}{cls.CHALLENGE_WELL_KNOWN_PATH}"
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    req = urllib.request.Request(
                        challenge_url,
                        headers={"User-Agent": "CyberAudit-Verification/2.0"},
                    )
                    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as response:
                        if response.status == 200:
                            content = response.read(256).decode("utf-8", errors="ignore").strip()
                            if expected_token in content:
                                return True
                except Exception:
                    continue

        return False
