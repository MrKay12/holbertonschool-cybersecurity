#!/usr/bin/env python3
"""Helper functions for NetProbe: service guessing and vuln check."""

import socket as skt


def guess_service(ip: str, port: int) -> str:
    """If banner is Unknown, try to guess service on port

    Args:
        ip: Target IP
        port: Port to scan

    Returns:
        Guessed service or "No Guessed Service"
    """
    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL"
    }

    if port in COMMON_PORTS.keys():
        return f"{COMMON_PORTS.get(port)}"
    else:
        return "No Service Guessed"


def check_vulnerability(banner: str) -> str:
    """Checks for a potential backdoor with the banner

    Args:
        banner: The actual banner to test

    Returns:
        Banner Vulnerability Check
    """
    BAD_SIGNS = {
        "vsftpd 2.3.4",
        "vsftpd 3.0.5",
        "Apache 2.2.8"
    }

    for sign in BAD_SIGNS:
        if banner.lower() in sign.lower():
            return "[VULNERABLE]"

    return ""


def ip_to_hostname(ip: str) -> str:
    """Convert IP to domain name

    Args:
        ip: IP to convert with DNS

    Returns:
        Domain name or failed resolution state
    """
    try:
        return skt.gethostbyaddr(ip)
    except skt.herror:
        return "Resolution failed"
