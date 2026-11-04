#!/usr/bin/env python3
"""Data model for IntelBroker: the TargetDossier class.

A TargetDossier aggregates every source (VirusTotal, Shodan, AbuseIPDB,
Nmap) about one target and can be printed or exported to JSON.
"""
import json
from datetime import datetime, timezone

from utils import UNAVAILABLE_MESSAGE


class TargetDossier:
    """Consolidated intelligence report about a single target.

    Attributes:
        ip (str): IP address or domain of the target.
        vt_data (dict): VirusTotal reputation data.
        abuse_data (dict): AbuseIPDB abuse data.
        nmap_ports (list): open ports found by Nmap.
        shodan_data (dict): Shodan historical data.
    """

    ip = ""
    vt_data = {}
    abuse_data = {}
    nmap_ports = []
    shodan_data = {}

    def __init__(self, ip: str = "", vt_data: dict = None,
                 abuse_data: dict = None, nmap_ports: list = None,
                 shodan_data: dict = None) -> None:
        """Create a dossier for a target, optionally pre-filled.

        Input: ip (str) - IP address or domain (default: empty string).
               vt_data (dict) - VirusTotal data (default: empty dict).
               abuse_data (dict) - AbuseIPDB data (default: empty dict).
               nmap_ports (list) - open ports (default: empty list).
               shodan_data (dict) - Shodan data (default: empty dict).
        Output: None.
        """
        self.ip = ip
        self.vt_data = vt_data if vt_data is not None else {}
        self.abuse_data = abuse_data if abuse_data is not None else {}
        self.nmap_ports = nmap_ports if nmap_ports is not None else []
        self.shodan_data = shodan_data if shodan_data is not None else {}

    def summary(self) -> str:
        """Build a human-readable summary of the dossier.

        A source that failed is shown as "Unavailable".

        Input: None.
        Output: str - multi-line summary of all collected data.
        """
        lines = [f"===== Dossier: {self.ip} ====="]
        if "error" in self.vt_data:
            lines.append(f"[VirusTotal] {UNAVAILABLE_MESSAGE}")
        else:
            lines.append(
                f"[VirusTotal] Score: "
                f"{self.vt_data.get('reputation_score', 'N/A')}/10 | "
                f"Malicious: {self.vt_data.get('malicious', 'N/A')}")
        if "error" in self.abuse_data:
            lines.append(f"[AbuseIPDB]  {UNAVAILABLE_MESSAGE}")
        else:
            lines.append(
                f"[AbuseIPDB]  Confidence: "
                f"{self.abuse_data.get('abuse_confidence_score', 'N/A')}% | "
                f"Reports: {self.abuse_data.get('reports', 'N/A')}")
        if "error" in self.shodan_data:
            lines.append(f"[Shodan]     {UNAVAILABLE_MESSAGE}")
        else:
            shodan_ports = ", ".join(
                str(port) for port in self.shodan_data.get("ports", []))
            lines.append(
                f"[Shodan]     OS: {self.shodan_data.get('os', 'N/A')} | "
                f"ISP: {self.shodan_data.get('isp', 'N/A')} | "
                f"Ports: {shodan_ports or 'none'}")
        ports = ", ".join(str(port) for port in self.nmap_ports)
        lines.append(f"[Nmap]       Open ports: {ports or 'none'}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Convert the dossier into a JSON-serializable dictionary.

        Input: None.
        Output: dict - {'target', 'timestamp', 'intelligence'}.
        """
        return {
            "target": self.ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "intelligence": {
                "virustotal": self.vt_data,
                "shodan": self.shodan_data,
                "abuseipdb": self.abuse_data,
                "nmap": {"ports": self.nmap_ports},
            },
        }

    def save_json(self, output_path: str) -> bool:
        """Save the dossier as a JSON report.

        Input: output_path (str) - path of the JSON file to write.
        Output: bool - True if the file was written, False on error.
        """
        try:
            with open(output_path, "w", encoding="utf-8") as report_file:
                json.dump(self.to_dict(), report_file, indent=2)
                report_file.write("\n")
        except OSError as error:
            print(f"[ERROR] Cannot write report to {output_path}: "
                  f"{error.strerror}")
            return False
        return True
