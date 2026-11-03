#!/usr/bin/env python3
"""IntelBroker: automated reconnaissance and threat-intel enrichment tool.

Queries a local mock Threat Intelligence API (localhost:5000),
runs a local Nmap scan, and returns the results to the caller.
"""
import subprocess
import xml.etree.ElementTree as ET

import requests

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


if __name__ == "__main__":
    print(query_virustotal("1.2.3.4"))
    print(query_abuseipdb("1.2.3.4"))
    try:
        print(parse_nmap_xml(run_nmap("127.0.0.1")))
    except RuntimeError as error:
        print(f"[ERROR] {error}")
