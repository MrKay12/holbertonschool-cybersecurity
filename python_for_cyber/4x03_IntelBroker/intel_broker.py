#!/usr/bin/env python3
"""IntelBroker: automated reconnaissance and threat-intel enrichment tool.

Queries a local mock Threat Intelligence API (localhost:5000),
runs a local Nmap scan, and aggregates everything into a TargetDossier.
API results are cached for 1 hour in cache.json.

Usage: ./intel_broker.py <IP or domain> [-o report.json]
"""
import argparse
import asyncio
import json
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    import requests
except ImportError:
    requests = None

API_BASE_URL = "http://localhost:5000"
REQUEST_TIMEOUT = 5
NMAP_PORTS = "22,80"
NMAP_TIMEOUT = 120
CACHE_FILE = "cache.json"
CACHE_TTL = 3600


def load_cache(cache_path: str = None) -> dict:
    """Load the JSON cache from disk.

    Input: cache_path (str) - cache file (default: CACHE_FILE).
    Output: dict - cache content, or an empty dict if the file is
            missing, unreadable or corrupted.
    """
    try:
        with open(cache_path or CACHE_FILE, "r", encoding="utf-8") as file:
            cache = json.load(file)
    except (OSError, ValueError):
        return {}
    return cache if isinstance(cache, dict) else {}


def save_cache(cache: dict, cache_path: str = None) -> bool:
    """Write the cache to disk (best effort, never raises).

    Input: cache (dict) - cache content to save.
           cache_path (str) - cache file (default: CACHE_FILE).
    Output: bool - True if the file was written, False otherwise.
    """
    try:
        with open(cache_path or CACHE_FILE, "w", encoding="utf-8") as file:
            json.dump(cache, file, indent=2)
            file.write("\n")
    except (OSError, TypeError, ValueError):
        return False
    return True


def get_cached(cache: dict, service: str, ip: str) -> dict:
    """Return cached data for a service/IP if it is less than 1 hour old.

    Input: cache (dict) - loaded cache.
           service (str) - API name (e.g. "virustotal").
           ip (str) - IP address or domain.
    Output: dict - cached payload, or None if missing or expired.
    """
    entry = cache.get(ip, {}).get(service)
    if not isinstance(entry, dict):
        return None
    try:
        age = time.time() - float(entry.get("timestamp", 0))
    except (TypeError, ValueError):
        return None
    if 0 <= age < CACHE_TTL and isinstance(entry.get("data"), dict):
        return entry["data"]
    return None


def set_cached(cache: dict, service: str, ip: str, data: dict) -> None:
    """Store a fresh API result in the cache (in memory).

    Input: cache (dict) - loaded cache, modified in place.
           service (str) - API name.
           ip (str) - IP address or domain.
           data (dict) - payload to store.
    Output: None.
    """
    cache.setdefault(ip, {})[service] = {"timestamp": time.time(),
                                         "data": data}


async def fetch_api(session, url: str) -> dict:
    """Send an asynchronous GET request and return the JSON payload.

    Input: session (aiohttp.ClientSession) - open HTTP session.
           url (str) - full URL of the API endpoint.
    Output: dict - JSON payload from the API, or an empty dict on error.
    """
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    try:
        async with session.get(url, timeout=timeout) as response:
            if response.status != 200:
                print(f"[ERROR] {url} returned status {response.status}.")
                return {}
            return await response.json()
    except aiohttp.ClientConnectorError:
        print("[ERROR] Cannot connect to the API. Is mock_api.py running?")
    except asyncio.TimeoutError:
        print(f"[ERROR] Request to {url} timed out.")
    except (aiohttp.ContentTypeError, ValueError):
        print(f"[ERROR] Invalid JSON received from {url}.")
    except aiohttp.ClientError as error:
        print(f"[ERROR] Request failed: {error}")
    return {}


async def fetch_api_limited(semaphore, session, url: str) -> dict:
    """Call fetch_api only when the semaphore grants a free slot.

    Input: semaphore (asyncio.Semaphore) - limits concurrent requests.
           session (aiohttp.ClientSession) - open HTTP session.
           url (str) - full URL of the API endpoint.
    Output: dict - JSON payload from the API, or an empty dict on error.
    """
    async with semaphore:
        return await fetch_api(session, url)


async def fetch_service(service: str, ip: str) -> dict:
    """Open a session and query one mock Threat Intel service.

    Input: service (str) - API name (e.g. "virustotal", "abuseipdb").
           ip (str) - IP address or domain to look up.
    Output: dict - JSON payload from the API, or an empty dict on error.
    """
    async with aiohttp.ClientSession() as session:
        return await fetch_api(session, f"{API_BASE_URL}/{service}/{ip}")


def fetch_api_sync(url: str) -> dict:
    """Fallback: send a blocking GET request with requests.

    Input: url (str) - full URL of the API endpoint.
    Output: dict - JSON payload from the API, or an empty dict on error.
    """
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            print(f"[ERROR] {url} returned status {response.status_code}.")
            return {}
        return response.json()
    except requests.exceptions.ConnectionError:
        print("[ERROR] Cannot connect to the API. Is mock_api.py running?")
    except requests.exceptions.Timeout:
        print(f"[ERROR] Request to {url} timed out.")
    except ValueError:
        print(f"[ERROR] Invalid JSON received from {url}.")
    except requests.exceptions.RequestException as error:
        print(f"[ERROR] Request failed: {error}")
    return {}


def query_api(service: str, ip: str) -> dict:
    """Synchronous helper to query one mock Threat Intel service.

    Returns cached data if it is less than 1 hour old. Otherwise uses
    aiohttp (via asyncio.run) when available, or falls back to requests,
    and saves the fresh result to the cache.

    Input: service (str) - API name (e.g. "virustotal", "abuseipdb").
           ip (str) - IP address or domain to look up.
    Output: dict - JSON payload from the API, or an empty dict on error.
    """
    cache = load_cache()
    cached_data = get_cached(cache, service, ip)
    if cached_data is not None:
        return cached_data
    if aiohttp is not None:
        data = asyncio.run(fetch_service(service, ip))
    elif requests is not None:
        data = fetch_api_sync(f"{API_BASE_URL}/{service}/{ip}")
    else:
        print("[ERROR] Neither 'aiohttp' nor 'requests' is installed.")
        return {}
    if data:
        set_cached(cache, service, ip, data)
        save_cache(cache)
    return data


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


def query_shodan(ip: str) -> dict:
    """Ask the mock Shodan API for historical data about an IP.

    Input: ip (str) - IP address or domain to look up.
    Output: dict - {'ip', 'ports', 'os', 'isp'}, or {} on error.
    """
    return query_api("shodan", ip)


async def gather_intel(ip: str) -> dict:
    """Query VirusTotal, Shodan and AbuseIPDB in parallel (with cache).

    Results less than 1 hour old are read from the cache; only the
    missing or expired ones are fetched, then saved to the cache.
    An asyncio.Semaphore limits the API calls to 5 at the same time.

    Input: ip (str) - IP address or domain to look up.
    Output: dict - {'virustotal': dict, 'shodan': dict, 'abuseipdb': dict};
            a source that failed is an empty dict.
    """
    services = ["virustotal", "shodan", "abuseipdb"]
    cache = load_cache()
    intel = {}
    to_fetch = []
    for service in services:
        cached_data = get_cached(cache, service, ip)
        if cached_data is not None:
            intel[service] = cached_data
        else:
            to_fetch.append(service)
    if not to_fetch:
        return intel
    if aiohttp is None:
        for service in to_fetch:
            intel[service] = {}
        return intel
    semaphore = asyncio.Semaphore(5)
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_api_limited(semaphore, session,
                                   f"{API_BASE_URL}/{service}/{ip}")
                 for service in to_fetch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    for service, result in zip(to_fetch, results):
        if isinstance(result, Exception):
            print(f"[ERROR] {service} query failed: {result}")
            result = {}
        intel[service] = result
        if result:
            set_cached(cache, service, ip, result)
    save_cache(cache)
    return {service: intel[service] for service in services}


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


async def run_nmap_async(ip: str) -> str:
    """Run the Nmap scan asynchronously and capture the XML output stream.

    Input: ip (str) - IP address or domain to scan.
    Output: str - raw Nmap XML report (stdout).
    Raises: RuntimeError if nmap is missing, times out,
            or exits with a non-zero return code.
    """
    try:
        process = await asyncio.create_subprocess_exec(
            "nmap", "-p", NMAP_PORTS, ip, "-oX", "-",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError:
        raise RuntimeError("nmap is not installed or not in PATH.")
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(),
                                                timeout=NMAP_TIMEOUT)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise RuntimeError(f"nmap scan timed out after {NMAP_TIMEOUT}s.")
    if process.returncode != 0:
        error_message = stderr.decode(errors="replace").strip()
        raise RuntimeError(f"nmap failed (code {process.returncode}): "
                           f"{error_message or 'unknown error'}")
    return stdout.decode(errors="replace")


async def scan_ports(ip: str) -> list:
    """Run the async Nmap scan and return the open ports.

    Input: ip (str) - IP address or domain to scan.
    Output: list - open ports (empty list if the scan failed).
    """
    try:
        return parse_nmap_xml(await run_nmap_async(ip))
    except RuntimeError as error:
        print(f"[ERROR] {error}")
        return []


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

        Input: None.
        Output: str - multi-line summary of all collected data.
        """
        vt_score = self.vt_data.get("reputation_score", "N/A")
        vt_malicious = self.vt_data.get("malicious", "N/A")
        abuse_score = self.abuse_data.get("abuse_confidence_score", "N/A")
        abuse_reports = self.abuse_data.get("reports", "N/A")
        shodan_os = self.shodan_data.get("os", "N/A")
        shodan_isp = self.shodan_data.get("isp", "N/A")
        shodan_ports = ", ".join(
            str(port) for port in self.shodan_data.get("ports", [])) or "none"
        ports = ", ".join(str(port) for port in self.nmap_ports) or "none"
        lines = [
            f"===== Dossier: {self.ip} =====",
            f"[VirusTotal] Score: {vt_score}/10 | Malicious: {vt_malicious}",
            f"[AbuseIPDB]  Confidence: {abuse_score}% | "
            f"Reports: {abuse_reports}",
            f"[Shodan]     OS: {shodan_os} | ISP: {shodan_isp} | "
            f"Ports: {shodan_ports}",
            f"[Nmap]       Open ports: {ports}",
        ]
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


async def build_dossier_async(ip: str) -> TargetDossier:
    """Run the 3 API queries AND the Nmap scan at the same time.

    Input: ip (str) - IP address or domain of the target.
    Output: TargetDossier - object filled with all collected data.
    """
    intel, open_ports = await asyncio.gather(gather_intel(ip),
                                             scan_ports(ip))
    return TargetDossier(ip,
                         vt_data=intel["virustotal"],
                         abuse_data=intel["abuseipdb"],
                         nmap_ports=open_ports,
                         shodan_data=intel["shodan"])


def build_dossier(ip: str) -> TargetDossier:
    """Synchronous entry point: run build_dossier_async in an event loop.

    Input: ip (str) - IP address or domain of the target.
    Output: TargetDossier - object filled with all collected data.
    """
    return asyncio.run(build_dossier_async(ip))


def main(argv: list = None) -> TargetDossier:
    """Parse the CLI arguments, build the dossier and print its summary.

    Input: argv (list) - CLI arguments (default: sys.argv[1:]),
           a single IP string is also accepted.
    Output: TargetDossier - the filled dossier (summary printed to stdout,
            JSON report written if --output is given).
    """
    if isinstance(argv, str):
        argv = [argv]
    parser = argparse.ArgumentParser(
        description="IntelBroker - automated IP reconnaissance tool.")
    parser.add_argument("ip", help="target IP address or domain")
    parser.add_argument("-o", "--output",
                        help="save the full dossier to this JSON file")
    args = parser.parse_args(argv)
    try:
        dossier = build_dossier(args.ip)
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user.")
        sys.exit(1)
    print(dossier.summary())
    if args.output and dossier.save_json(args.output):
        print(f"[INFO] Report saved to {args.output}")
    return dossier


if __name__ == "__main__":
    main()
