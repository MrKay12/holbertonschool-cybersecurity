#!/usr/bin/env python3
"""IntelBroker: automated reconnaissance and threat-intel enrichment tool.

Queries a local mock Threat Intelligence API (localhost:5000),
runs a local Nmap scan, and aggregates everything into a TargetDossier.

Usage: ./intel_broker.py <IP or domain>
"""
import argparse
import subprocess
import sys
import xml.etree.ElementTree as ET

try:
    import requests
except ImportError:
    requests = None

API_BASE_URL = "http://localhost:5000"
REQUEST_TIMEOUT = 5
NMAP_PORTS = "22,80"
NMAP_TIMEOUT = 120


def query_api(service: str, ip: str) -> dict:
    """Send a GET request to a mock Threat Intel service.

    Input: service (str) - API name (e.g. "virustotal", "abuseipdb").
           ip (str) - IP address or domain to look up.
    Output: dict - JSON payload from the API, or an empty dict on error.
    """
    if requests is None:
        print("[ERROR] The 'requests' library is not installed.")
        return {}
    url = f"{API_BASE_URL}/{service}/{ip}"
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            print(f"[ERROR] {service} returned status "
                  f"{response.status_code}.")
            return {}
        return response.json()
    except requests.exceptions.ConnectionError:
        print("[ERROR] Cannot connect to the API. Is mock_api.py running?")
    except requests.exceptions.Timeout:
        print(f"[ERROR] {service} request timed out.")
    except ValueError:
        print(f"[ERROR] Invalid JSON received from {service}.")
    except requests.exceptions.RequestException as error:
        print(f"[ERROR] Request failed: {error}")
    return {}


def query_virustotal(ip: str) -> dict:
    """Ask the mock VirusTotal API for the reputation of an IP.

    Input: ip (str) - IP address or domain to look up.
    Output: dict - {'ip', 'reputation_score', 'malicious'}, or {} on error.
    """
    return query_api("virustotal", ip)


def query_abuseipdb(ip: str) -> dict:
    """Ask the mock AbuseIPDB API for the abuse score of an IP.

    Input: ip (str) - IP address or domain to look up.
    Output: dict - {'ip', 'abuse_confidence_score', 'reports'},
            or {} on error.
    """
    return query_api("abuseipdb", ip)


def run_nmap(ip: str) -> str:
    """Run an Nmap scan on ports 22 and 80 and capture the XML output.

    Input: ip (str) - IP address or domain to scan.
    Output: str - raw Nmap XML report (stdout).
    Raises: RuntimeError if nmap is missing, times out,
            or exits with a non-zero return code.
    """
    command = ["nmap", "-p", NMAP_PORTS, ip, "-oX", "-"]
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=NMAP_TIMEOUT)
    except FileNotFoundError:
        raise RuntimeError("nmap is not installed or not in PATH.")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"nmap scan timed out after {NMAP_TIMEOUT}s.")
    if result.returncode != 0:
        error_message = result.stderr.strip() or "unknown error"
        raise RuntimeError(f"nmap failed (code {result.returncode}): "
                           f"{error_message}")
    return result.stdout


def parse_nmap_xml(xml_data: str) -> list:
    """Extract the open ports from an Nmap XML report.

    Input: xml_data (str) - raw XML produced by `nmap -oX -`.
    Output: list - open port numbers as integers (e.g. [22, 80]),
            or an empty list if the XML is invalid.
    """
    open_ports = []
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        print("[ERROR] Invalid Nmap XML output.")
        return open_ports
    for port in root.findall("host/ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        try:
            open_ports.append(int(port.get("portid", "")))
        except ValueError:
            continue
    return open_ports


class TargetDossier:
    """Consolidated intelligence report about a single target.

    Attributes:
        ip (str): IP address or domain of the target.
        vt_data (dict): VirusTotal reputation data.
        abuse_data (dict): AbuseIPDB abuse data.
        nmap_ports (list): open ports found by Nmap.
    """

    ip = ""
    vt_data = {}
    abuse_data = {}
    nmap_ports = []

    def __init__(self, ip: str = "", vt_data: dict = None,
                 abuse_data: dict = None, nmap_ports: list = None) -> None:
        """Create a dossier for a target, optionally pre-filled.

        Input: ip (str) - IP address or domain (default: empty string).
               vt_data (dict) - VirusTotal data (default: empty dict).
               abuse_data (dict) - AbuseIPDB data (default: empty dict).
               nmap_ports (list) - open ports (default: empty list).
        Output: None.
        """
        self.ip = ip
        self.vt_data = vt_data if vt_data is not None else {}
        self.abuse_data = abuse_data if abuse_data is not None else {}
        self.nmap_ports = nmap_ports if nmap_ports is not None else []

    def summary(self) -> str:
        """Build a human-readable summary of the dossier.

        Input: None.
        Output: str - multi-line summary of all collected data.
        """
        vt_score = self.vt_data.get("reputation_score", "N/A")
        vt_malicious = self.vt_data.get("malicious", "N/A")
        abuse_score = self.abuse_data.get("abuse_confidence_score", "N/A")
        abuse_reports = self.abuse_data.get("reports", "N/A")
        ports = ", ".join(str(port) for port in self.nmap_ports) or "none"
        lines = [
            f"===== Dossier: {self.ip} =====",
            f"[VirusTotal] Score: {vt_score}/10 | Malicious: {vt_malicious}",
            f"[AbuseIPDB]  Confidence: {abuse_score}% | "
            f"Reports: {abuse_reports}",
            f"[Nmap]       Open ports: {ports}",
        ]
        return "\n".join(lines)


def build_dossier(ip: str) -> TargetDossier:
    """Run the VT, AbuseIPDB and Nmap queries sequentially.

    Input: ip (str) - IP address or domain of the target.
    Output: TargetDossier - object filled with all collected data.
    """
    dossier = TargetDossier(ip)
    dossier.vt_data = query_virustotal(ip)
    dossier.abuse_data = query_abuseipdb(ip)
    try:
        dossier.nmap_ports = parse_nmap_xml(run_nmap(ip))
    except RuntimeError as error:
        print(f"[ERROR] {error}")
    return dossier


def main(argv: list = None) -> TargetDossier:
    """Parse the CLI argument, build the dossier and print its summary.

    Input: argv (list) - CLI arguments (default: sys.argv[1:]),
           a single IP string is also accepted.
    Output: TargetDossier - the filled dossier (summary printed to stdout).
    """
    if isinstance(argv, str):
        argv = [argv]
    parser = argparse.ArgumentParser(
        description="IntelBroker - automated IP reconnaissance tool.")
    parser.add_argument("ip", help="target IP address or domain")
    args = parser.parse_args(argv)
    try:
        dossier = build_dossier(args.ip)
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user.")
        sys.exit(1)
    print(dossier.summary())
    return dossier


if __name__ == "__main__":
    main()
