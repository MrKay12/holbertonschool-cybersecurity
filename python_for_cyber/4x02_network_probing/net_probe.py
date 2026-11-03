#!/usr/bin/env python3

import argparse
import concurrent.futures as crtf
import json
import random
import socket as skt
import time


def check_port(ip: str, port: int, local_ip: str = None) -> bool:
    """Checks the availability of a target

    Args:
        ip: IP Host to test (or hostname)
        port: Target port

    Returns:
        True if port is open else False
    """
    try:
        s = skt.socket(skt.AF_INET, skt.SOCK_STREAM)
        s.settimeout(1)

        if local_ip is not None:
            s.bind((local_ip, 0))
            print("[INFO] Scanning from source:", local_ip)
        s.connect((ip, port))

        return True
    except (OSError, TimeoutError):
        return False
    finally:
        if s:
            s.close()


def ping_sweep(subnet: str) -> list[str]:
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
    try:
        s = skt.socket(skt.AF_INET, skt.SOCK_STREAM)
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
               shuffle: bool = False,
               interface: bool = False) -> list:
    """Scan a range of ports

    Args:
        ip: Target IP
        start_port: Lower band port to scan
        end_port: Lower band port to scan

    Returns:
        Open ports report with banner grabbing
    """
    # print(f"Scanning {ip} from {start_port} to {end_port}...")
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

    # print_infos(ip, ports_report)
    return ports_report


def print_infos(ip, ports_analysis: list[dict]) -> None:
    """Print informations after analysis

    Args:
        ip: Target IP
        ports_analysis: extracted ports
    """
    if ports_analysis:
        for port in ports_analysis:
            if port:
                print(
                    f"[+] Port {port['port']}: "
                    f"{guess_service(ip, port['port'])} "
                    f"({port['service']})"
                    f"{check_vulnerability(port['service'])}"
                )
    else:
        print("No Port Discovered")


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

    # banner = get_banner(ip, port)
    # if banner == "Unknown":
    if port in COMMON_PORTS.keys():
        return f"{COMMON_PORTS.get(port)}"
    else:
        return "No Service Guessed"

    # return ""


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


def generate_json_report(ip: str,
                         domain: str,
                         filename: str,
                         ports_analytics: list[dict]) -> None:
    """Generate human-readable report with JSON format

    Args:
        filename: path or direct filename to write
        ports_analytics: data to write
    """
    infos = f"{ip} ({domain})"
    ports_analytics.insert(0, {'target': infos})
    to_json_str_data = json.dumps(ports_analytics, indent=2)

    with open(filename, "w") as file:
        file.write(to_json_str_data)
        file.write('\n')


def scan_udp(ip: str, port: int):
    """Checks the availability of a target

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


def main() -> None:
    """Program Entry Point"""
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target",
                        help="Target IP",
                        required=True)
    parser.add_argument("-p", "--ports",
                        required=True,
                        help="Port range to scan")
    parser.add_argument("-o", "--output",
                        help="Generate report to file")
    parser.add_argument("-d", "--delay", type=float,
                        help="Set a delay between ports analysis")
    parser.add_argument("-r", "--random", action="store_true",
                        help="Shuffle the list of ports")
    parser.add_argument("-i", "--interface",
                        help="Interface to use (for binding)")

    args = parser.parse_args()
    sep_port = args.ports.find('-')

    ip = args.target
    lower_port = int(args.ports[:sep_port])
    upper_port = int(args.ports[sep_port + 1:])

    delay = 0.0
    if args.delay:
        delay = float(args.delay)

    if args.random:
        shuffle_set = True
    else:
        shuffle_set = False

    if args.interface:
        interface = args.interface
    else:
        interface = None

    ports = scan_ports(ip,
                       lower_port,
                       upper_port,
                       delay=delay,
                       shuffle=shuffle_set)

    domain = skt.gethostbyaddr(ip)[0]
    print(f"Target: {ip} ({domain})")

    if args.output:
        generate_json_report(ip,
                             domain,
                             args.output,
                             ports)


if __name__ == '__main__':
    main()
