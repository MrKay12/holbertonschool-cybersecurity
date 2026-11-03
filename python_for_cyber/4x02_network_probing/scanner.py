#!/usr/bin/env python3
"""Socket logic for NetProbe: port checking and banner grabbing."""

import concurrent.futures as crtf
import random
import socket as skt
import time

from utils import check_vulnerability, guess_service

INTERFACE = None


def check_port(ip: str, port: int) -> bool:
    """Checks the availability of a target

    Args:
        ip: IP Host to test (or hostname)
        port: Target port

    Returns:
        True if port is open else False
    """
    s = None
    try:
        s = skt.socket(skt.AF_INET, skt.SOCK_STREAM)
        s.settimeout(1)

        if INTERFACE is not None:
            s.bind((INTERFACE, 0))
        s.connect((ip, port))

        return True
    except (OSError, TimeoutError):
        return False
    finally:
        if s:
            s.close()


def ping_sweep(subnet: str) -> list:
    """Checks addresses with port 80 open

    Args:
        subnet: Network section, CIDR is supposed 24

    Returns:
        List of success IPs test
    """
    list_ip = []

    for e in range(1, 255):
        address = f"{subnet}.{e}"
        is_port_open = check_port(address, 8000)
        if is_port_open:
            list_ip.append(address)

    return list_ip


def get_banner(ip: str, port: int) -> str:
    """Extract banner from application-level protocol / service

    Args:
        ip: Target IP
        port: Port to scan

    Returns:
        Banner if succesfully handled else Unknown
    """
    s = None
    try:
        s = skt.socket(skt.AF_INET, skt.SOCK_STREAM)
        if INTERFACE is not None:
            s.bind((INTERFACE, 0))
        s.connect((ip, port))

        if port == 80:
            req = (
                "GET / HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                "\r\n"
            ).encode()
            s.send(req)

            data = s.recv(1024)
            if not data:
                return "Unknown"

            banner = data.decode().strip()
            for line in banner.split('\n'):
                if "Server" in line.replace('\r', ''):
                    return line.removeprefix('Server: ').removesuffix('\r')

            return "Unknown"
        elif port == 22:
            data = s.recv(1024)
            if not data:
                return "Unknown"

            banner = data.decode().strip()
            banner = banner.replace('\r', '')
            return banner.split()[0]
        elif port == 21:
            s.send(f"ftp {ip}".encode())
            data = s.recv(1024)
            if not data:
                return "Unknown"

            banner = data.decode().strip()
            for line in banner.split('\n'):
                if line.startswith('220'):
                    banner = line.removeprefix('220').removesuffix(')')
                    banner = banner.strip().removeprefix('(').lower()
                    return banner

            return "Unknown"
        else:
            return "Unknown"
    except OSError:
        print("[ERROR] Socket process problem occured")
        return "Unknown"
    except TimeoutError:
        print("Socket timeout reached")
        return "Unknown"
    finally:
        if s:
            s.close()


def scan_single_port(ip: str, port: int, delay: float) -> dict:
    """Get one port state

    Args:
        ip: Target IP
        port: Single port to scan

    Returns:
        Metadata dictionary or empty one if port is not open
    """
    if delay > 0.0:
        print(f"[DEBUG] {port} - Sleeping {delay} before next packet...")
        time.sleep(delay)

    is_open_port = check_port(ip, port)

    if is_open_port:
        banner = get_banner(ip, port)
        if check_vulnerability(banner):
            is_vulnerable_banner = 'YES'
        else:
            is_vulnerable_banner = 'NO'

        return {
            'port': port,
            'state': 'open',
            'service': banner,
            'vulnerability': is_vulnerable_banner
        }

    return {}


def scan_ports(ip: str,
               start_port: int,
               end_port: int,
               delay: float,
               shuffle: bool = False) -> list:
    """Scan a range of ports

    Args:
        ip: Target IP
        start_port: Lower band port to scan
        end_port: Lower band port to scan

    Returns:
        Open ports report with banner grabbing
    """
    ports_report = []

    with crtf.ThreadPoolExecutor(max_workers=50) as executor:
        ports_list = list(range(start_port, end_port + 1))
        if shuffle:
            random.shuffle(ports_list)

        for port in ports_list:
            future = executor.submit(scan_single_port,
                                     ip, port, delay)

            try:
                data = future.result()
                if data:
                    ports_report.append(data)
            except Exception as e:
                print(f"Error occured!\n{e}")

    return ports_report


def scan_udp(ip: str, port: int) -> bool:
    """Checks the availability of a UDP target

    Args:
        ip: IP Host to test (or hostname)
        port: Target port

    Returns:
        True if port is open else False
    """
    s = None
    try:
        s = skt.socket(skt.AF_INET, skt.SOCK_DGRAM)
        s.settimeout(3)

        s.sendto(b'', (ip, port))
        data, addr = s.recvfrom(1024)

        if not data:
            return False
        return True
    except skt.gaierror:
        return False
    except TimeoutError:
        return False
    finally:
        if s is not None:
            s.close()
