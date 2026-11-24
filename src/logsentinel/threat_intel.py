"""Offline Threat Intelligence (IOC) enrichment engine."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path

from .models import Alert, Severity


@dataclass(slots=True)
class ThreatIntelFeed:
    """In-memory IOC feed for IP, CIDR, and User-Agent matching."""

    malicious_ips: dict[str, str] = field(default_factory=dict)
    tor_exit_nodes: set[str] = field(default_factory=set)
    malicious_cidrs: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = field(
        default_factory=list
    )
    suspicious_user_agents: list[str] = field(default_factory=list)

    @classmethod
    def from_json(cls, path: Path) -> "ThreatIntelFeed":
        """Load IOC indicators from a JSON feed file."""
        data = json.loads(path.read_text(encoding="utf-8"))
        cidrs = []
        for entry in data.get("malicious_cidrs", []):
            cidr_str = entry["cidr"] if isinstance(entry, dict) else entry
            label = entry.get("label", "Malicious CIDR") if isinstance(entry, dict) else "Malicious CIDR"
            cidrs.append((ipaddress.ip_network(cidr_str, strict=False), label))

        return cls(
            malicious_ips=dict(data.get("malicious_ips", {})),
            tor_exit_nodes=set(data.get("tor_exit_nodes", [])),
            malicious_cidrs=cidrs,
            suspicious_user_agents=[ua.lower() for ua in data.get("suspicious_user_agents", [])],
        )

    def lookup_ip(self, ip_str: str | None) -> list[str]:
        """Return threat-intel tags matching the given IP address."""
        if not ip_str:
            return []
        matches: list[str] = []
        if ip_str in self.malicious_ips:
            matches.append(f"Known Malicious IP ({self.malicious_ips[ip_str]})")
        if ip_str in self.tor_exit_nodes:
            matches.append("Tor Exit Node")
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for net, label in self.malicious_cidrs:
                if ip_obj in net:
                    matches.append(f"Malicious Network {net} ({label})")
        except ValueError:
            pass
        return matches

    def lookup_text_indicators(self, raw_samples: list[str]) -> list[str]:
        """Check sample raw log lines for suspicious user-agent signatures."""
        hits: list[str] = []
        joined = "\n".join(raw_samples).lower()
        for ua in self.suspicious_user_agents:
            if ua in joined:
                hits.append(f"Suspicious Tool/UA ({ua})")
        return hits

    def enrich_alerts(self, alerts: list[Alert]) -> list[Alert]:
        """Enrich alerts with IOC matches and boost risk scores/severity."""
        for alert in alerts:
            hits = self.lookup_ip(alert.source_ip)
            hits.extend(self.lookup_text_indicators(alert.sample_raw))
            if hits:
                # Preserve order while deduplicating
                alert.ioc_matches = list(dict.fromkeys(alert.ioc_matches + hits))
                boost = min(25, 12 * len(alert.ioc_matches))
                alert.risk_score = min(100, alert.risk_score + boost)
                upgraded = Severity.from_score(alert.risk_score)
                if upgraded.rank > alert.severity.rank:
                    alert.severity = upgraded
        return alerts
