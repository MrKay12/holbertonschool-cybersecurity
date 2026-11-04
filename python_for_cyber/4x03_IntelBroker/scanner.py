#!/usr/bin/env python3
"""Nmap wrapper for IntelBroker.

Runs `nmap -p 22,80 <target> -oX -` (blocking or asynchronous)
and extracts the open ports from the XML report.
"""
import asyncio
import subprocess
import xml.etree.ElementTree as ET

from utils import log_status

NMAP_PORTS = "22,80"
NMAP_TIMEOUT = 120


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


async def scan_ports(ip: str, verbose: bool = False) -> list:
    """Run the async Nmap scan and return the open ports.

    Input: ip (str) - IP address or domain to scan.
           verbose (bool) - print status messages (default: False).
    Output: list - open ports (empty list if the scan failed).
    """
    log_status(f"[+] Running Nmap on {ip}...", verbose)
    try:
        xml_data = await run_nmap_async(ip)
    except RuntimeError as error:
        print(f"[ERROR] {error}")
        return []
    log_status("[+] Nmap finished.", verbose)
    return parse_nmap_xml(xml_data)
