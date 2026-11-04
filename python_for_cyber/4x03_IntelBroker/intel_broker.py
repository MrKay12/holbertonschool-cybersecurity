#!/usr/bin/env python3
"""IntelBroker: automated reconnaissance and threat-intel enrichment tool.

Entry point. Combines the async API client (api_client.py), the Nmap
wrapper (scanner.py) and the TargetDossier model (models.py).

Usage: ./intel_broker.py <IP or domain> [-o report.json] [-v]
"""
import argparse
import asyncio
import sys

from api_client import (fetch_api, gather_intel, query_abuseipdb,
                        query_shodan, query_virustotal)
from models import TargetDossier
from scanner import parse_nmap_xml, run_nmap, run_nmap_async, scan_ports

__all__ = ["fetch_api", "gather_intel", "query_abuseipdb", "query_shodan",
           "query_virustotal", "TargetDossier", "parse_nmap_xml",
           "run_nmap", "run_nmap_async", "scan_ports",
           "build_dossier_async", "build_dossier", "main"]


async def build_dossier_async(ip: str,
                              verbose: bool = False) -> TargetDossier:
    """Run the 3 API queries AND the Nmap scan at the same time.

    Input: ip (str) - IP address or domain of the target.
           verbose (bool) - print status messages (default: False).
    Output: TargetDossier - object filled with all collected data.
    """
    intel, open_ports = await asyncio.gather(gather_intel(ip, verbose),
                                             scan_ports(ip, verbose))
    return TargetDossier(ip,
                         vt_data=intel["virustotal"],
                         abuse_data=intel["abuseipdb"],
                         nmap_ports=open_ports,
                         shodan_data=intel["shodan"])


def build_dossier(ip: str, verbose: bool = False) -> TargetDossier:
    """Synchronous entry point: run build_dossier_async in an event loop.

    Input: ip (str) - IP address or domain of the target.
           verbose (bool) - print status messages (default: False).
    Output: TargetDossier - object filled with all collected data.
    """
    return asyncio.run(build_dossier_async(ip, verbose))


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
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show status messages during the scan")
    args = parser.parse_args(argv)
    try:
        dossier = build_dossier(args.ip, args.verbose)
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user.")
        sys.exit(1)
    print(dossier.summary())
    if args.output:
        if dossier.save_json(args.output):
            print("[SUCCESS] Report generated.")
    elif args.verbose:
        print("[SUCCESS] Report generated.")
    return dossier


if __name__ == "__main__":
    main()
