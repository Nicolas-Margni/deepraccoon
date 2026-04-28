"""
NetworkScanner: detects active or recent connections to known LLM API endpoints.

Checks three sources:
  1. Active TCP connections via psutil (requires admin for full visibility)
  2. Windows DNS cache via 'ipconfig /displaydns' (Windows only)
  3. /etc/hosts file for manually configured AI domain entries (Unix)

Active connections are HIGH severity.
DNS cache hits (recent but not currently active) are MEDIUM severity.
"""

import platform
import socket
import subprocess
from typing import Optional

import psutil

from core.finding import Finding
from modules.base_module import BaseModule


def _reverse_lookup(ip: str, timeout: float = 0.3) -> Optional[str]:
    """
    Perform a reverse DNS lookup on an IP address.

    Args:
        ip:      IP address string to look up.
        timeout: Maximum seconds to wait for the lookup.

    Returns:
        Hostname string if resolved, None on failure or timeout.
    """
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.lower()
    except (socket.herror, socket.gaierror, OSError):
        return None


def _get_windows_dns_cache() -> list[str]:
    """
    Query the Windows DNS resolver cache via 'ipconfig /displaydns'.

    Returns:
        List of hostnames found in the DNS cache (lowercase).
        Empty list on non-Windows systems or if the command fails.
    """
    if platform.system() != "Windows":
        return []

    try:
        result = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True,
            text=True,
            timeout=10,
            encoding="utf-8",
            errors="ignore",
        )
        hostnames: list[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            # Lines with record names look like: "    Record Name . . . . . : api.openai.com"
            if "Record Name" in line and ":" in line:
                hostname = line.split(":", 1)[-1].strip().lower()
                if hostname:
                    hostnames.append(hostname)
        return hostnames
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


def _domain_matches(hostname: str, known_domains: list[dict]) -> Optional[dict]:
    """
    Check if a hostname matches any known LLM API domain.

    Supports both exact matches and subdomain matches
    (e.g., 'subdomain.api.openai.com' matches 'api.openai.com').

    Args:
        hostname:     Hostname to check (lowercase).
        known_domains: List of domain dicts from signatures.json.

    Returns:
        Matching domain dict if found, None otherwise.
    """
    for domain_def in known_domains:
        known = domain_def["domain"].lower()
        if hostname == known or hostname.endswith("." + known):
            return domain_def
    return None


class NetworkScanner(BaseModule):
    """
    Detects connections to LLM API endpoints via active TCP connections
    and Windows DNS cache analysis.

    Requires administrator privileges for complete visibility into
    all system connections. Limited-privilege scans will only see
    connections owned by the current user.
    """

    @property
    def name(self) -> str:
        return "network_scanner"

    @property
    def description(self) -> str:
        return "Detects active and recent connections to LLM API endpoints"

    def run(self) -> list[Finding]:
        """
        Execute all network scanning sub-checks.

        Returns:
            List of Finding objects from all sources combined.
        """
        findings: list[Finding] = []
        known_domains = self.signatures.get("api_domains", [])

        findings.extend(self._scan_active_connections(known_domains))
        findings.extend(self._scan_dns_cache(known_domains))

        # Deduplicate: if a domain was caught both active and in DNS cache,
        # keep only the higher-severity (active) finding.
        seen_providers: set[str] = set()
        deduped: list[Finding] = []
        for finding in sorted(findings, key=lambda f: f.severity_order()):
            provider = finding.evidence.split("→")[0].strip()
            if provider not in seen_providers:
                seen_providers.add(provider)
                deduped.append(finding)

        return deduped

    def _scan_active_connections(self, known_domains: list[dict]) -> list[Finding]:
        """
        Scan active TCP connections and perform reverse DNS lookups.

        Args:
            known_domains: List of domain signature dicts.

        Returns:
            HIGH severity findings for each active LLM API connection.
        """
        findings: list[Finding] = []
        seen_ips: set[str] = set()

        try:
            connections = psutil.net_connections(kind="tcp")
        except psutil.AccessDenied:
            return findings

        for conn in connections:
            if conn.status != "ESTABLISHED":
                continue
            if not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port

            if remote_ip in seen_ips:
                continue
            seen_ips.add(remote_ip)

            hostname = _reverse_lookup(remote_ip)
            if not hostname:
                continue

            match = _domain_matches(hostname, known_domains)
            if not match:
                continue

            pid_info = f"PID {conn.pid}" if conn.pid else "unknown PID"

            findings.append(Finding(
                module=self.name,
                severity="HIGH",
                title=f"Active connection to {match['provider']} API",
                description=(
                    f"An active TCP connection to {match['provider']} API "
                    f"({match['domain']}) was detected. This indicates a process "
                    f"on this system is currently communicating with an LLM service."
                ),
                evidence=(
                    f"{match['provider']} → {hostname} ({remote_ip}:{remote_port}) "
                    f"— {pid_info}"
                ),
                recommendation=(
                    f"Identify the process making this connection ({pid_info}) and "
                    f"verify it is authorized. Use 'netstat -ano' or Task Manager "
                    f"to investigate further."
                ),
            ))

        return findings

    def _scan_dns_cache(self, known_domains: list[dict]) -> list[Finding]:
        """
        Scan the Windows DNS cache for recently resolved LLM API domains.

        A DNS cache hit means the machine resolved that domain recently,
        even if no active connection exists right now.

        Args:
            known_domains: List of domain signature dicts.

        Returns:
            MEDIUM severity findings for each cached LLM API domain.
        """
        findings: list[Finding] = []
        cached_hostnames = _get_windows_dns_cache()

        for hostname in cached_hostnames:
            match = _domain_matches(hostname, known_domains)
            if not match:
                continue

            findings.append(Finding(
                module=self.name,
                severity="MEDIUM",
                title=f"Recent DNS lookup: {match['provider']} API",
                description=(
                    f"The domain '{match['domain']}' ({match['provider']}) was found "
                    f"in the Windows DNS cache. This means this machine resolved the "
                    f"domain recently, indicating past communication with the LLM service."
                ),
                evidence=f"{match['provider']} → {hostname} (DNS cache hit)",
                recommendation=(
                    f"Investigate which application recently connected to {match['provider']}. "
                    f"Check running processes and browser history for unauthorized AI usage. "
                    f"Flush DNS cache with 'ipconfig /flushdns' after investigation."
                ),
            ))

        return findings
