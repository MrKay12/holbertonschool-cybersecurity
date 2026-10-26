#!/usr/bin/env python3
"""LogHunter - Log Analysis Engine."""

import argparse
import re
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone


APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<date>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]+" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)"'
    r' "(?P<user_agent>[^"]*)")?'
)

SYSLOG_PATTERN = re.compile(
    r'^(?P<date>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) '
    r'(?P<host>\S+) (?P<service>[\w./-]+)'
    r'(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$'
)

IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

SSQLI_SIGNATURES = [
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r"'\s*or\s+'?1'?\s*=\s*'?1", re.IGNORECASE),
    re.compile(r"\bor\s+1\s*=\s*1", re.IGNORECASE),
    re.compile(r"\bselect\b.+\bfrom\b", re.IGNORECASE),
    re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
    re.compile(r"\binformation_schema\b", re.IGNORECASE),
    re.compile(r"\bsleep\s*\(", re.IGNORECASE),
    re.compile(r"\bbenchmark\s*\(", re.IGNORECASE),
    re.compile(r"%27\s*or", re.IGNORECASE),
]

XSS_SIGNATURES = [
    re.compile(r"<\s*script", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"onload\s*=", re.IGNORECASE),
    re.compile(r"onerror\s*=", re.IGNORECASE),
]

GEOIP_DB = {}

BOT_SIGNATURES = [
    "bot",
    "crawler",
    "spider",
    "nikto",
    "sqlmap",
    "nmap",
    "masscan",
    "curl",
    "wget",
]

BLACKLIST = set()


class LogEntry:
    """Represent a normalized log entry."""

    def __init__(
        self,
        ip=None,
        timestamp=None,
        service=None,
        message="",
        raw_line="",
        method=None,
        path=None,
        status=None,
        size=None,
        user_agent=None,
        source=None,
        country=None,
        is_bot=False,
        alert_level="INFO",
        attack_type=None,
    ):
        """Initialize a log entry."""
        self.ip = ip
        self.timestamp = timestamp
        self.service = service
        self.message = message
        self.raw_line = raw_line
        self.method = method
        self.path = path
        self.status = status
        self.size = size
        self.user_agent = user_agent
        self.source = source
        self.country = country
        self.is_bot = is_bot
        self.alert_level = alert_level
        self.attack_type = attack_type


def read_stream(file_path):
    """Yield lines from a log file."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            for line in file:
                yield line.rstrip("\n")
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
    except PermissionError:
        print(f"[ERROR] Permission denied: {file_path}")


def parse_apache_line(line):
    """Parse an Apache access log line."""
    match = APACHE_PATTERN.search(line)
    if not match:
        return None

    data = match.groupdict()
    return {
        "ip": data["ip"],
        "date": data["date"],
        "method": data["method"],
        "path": data["path"],
        "status": data["status"],
        "size": data["size"],
        "user_agent": data.get("user_agent") or "",
    }


def parse_syslog_line(line):
    """Parse a Syslog line."""
    match = SYSLOG_PATTERN.search(line)
    if not match:
        return None

    data = match.groupdict()
    ip_match = IP_PATTERN.search(data["message"])

    return {
        "ip": ip_match.group(0) if ip_match else None,
        "date": data["date"],
        "service": data["service"],
        "message": data["message"],
        "host": data["host"],
    }


def normalize_entry(line):
    """Parse a raw log line into a LogEntry object."""
    apache_data = parse_apache_line(line)

    if apache_data:
        return LogEntry(
            ip=apache_data["ip"],
            timestamp=apache_data["date"],
            service="apache",
            message=line,
            raw_line=line,
            method=apache_data["method"],
            path=apache_data["path"],
            status=apache_data["status"],
            size=apache_data["size"],
            user_agent=apache_data["user_agent"],
            source="apache",
        )

    syslog_data = parse_syslog_line(line)

    if syslog_data:
        return LogEntry(
            ip=syslog_data["ip"],
            timestamp=syslog_data["date"],
            service=syslog_data["service"],
            message=syslog_data["message"],
            raw_line=line,
            source="syslog",
        )

    return None


def filter_logs(entries, ip=None, status=None, service=None):
    """Filter entries by IP, status, or service."""
    for entry in entries:
        if ip and entry.ip != ip:
            continue

        if status is not None:
            if str(entry.status) != str(status):
                continue

        if service and entry.service != service:
            continue

        yield entry


def enrich_ip(entry):
    """Add GeoIP information when a record exists."""
    if entry.ip and entry.ip in GEOIP_DB:
        entry.country = GEOIP_DB[entry.ip]

    return entry


def analyze_user_agent(entry):
    """Identify entries that appear to come from automated tools."""
    user_agent = (entry.user_agent or "").lower()
    message = (entry.message or "").lower()

    for signature in BOT_SIGNATURES:
        if signature in user_agent or signature in message:
            entry.is_bot = True
            break

    return entry


def check_threat_intel(entry):
    """Check whether the entry IP appears on the local blacklist."""
    if entry.ip and entry.ip in BLACKLIST:
        entry.alert_level = "CRITICAL"

    return entry


def detect_sqli(log_entry):
    """Detect SQL injection patterns in a log entry."""
    if getattr(log_entry, "attack_type", None) is not None:
        return log_entry

    path = str(getattr(log_entry, "path", "") or "")
    message = str(getattr(log_entry, "message", "") or "")
    content = f"{path} {message}"

    for signature in SQLI_SIGNATURES:
        if signature.search(content):
            log_entry.attack_type = "SQLi"
            log_entry.alert_level = "CRITICAL"
            break

    return log_entry


def detect_xss(log_entry):
    """Detect cross-site scripting patterns in a log entry."""
    if getattr(log_entry, "attack_type", None) is not None:
        return log_entry

    path = str(getattr(log_entry, "path", "") or "")
    message = str(getattr(log_entry, "message", "") or "")
    content = f"{path} {message}"

    for signature in XSS_SIGNATURES:
        if signature.search(content):
            log_entry.attack_type = "XSS"
            log_entry.alert_level = "CRITICAL"
            break

    return log_entry


def detect_bruteforce(entries):
    """Yield alerts for IP addresses with repeated failed logins."""
    failures = Counter()

    for entry in entries:
        status = getattr(entry, "status", None)
        message = str(getattr(entry, "message", "") or "")

        try:
            failed_status = int(status) == 401
        except (TypeError, ValueError):
            failed_status = False

        failed_ssh = "Failed password" in message

        if (failed_status or failed_ssh) and entry.ip:
            failures[entry.ip] += 1

    for ip, count in failures.items():
        if count > 5:
            yield {
                "ip": ip,
                "count": count,
                "alert_type": "BRUTE_FORCE",
            }


def parse_timestamp(timestamp):
    """Parse Apache and Syslog timestamps."""
    if not timestamp:
        return None

    timestamp = str(timestamp).strip()

    try:
        parsed = datetime.strptime(
            timestamp,
            "%d/%b/%Y:%H:%M:%S %z",
        )
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        pass

    try:
        parsed = datetime.strptime(timestamp, "%b %d %H:%M:%S")
        return parsed.replace(year=datetime.now().year)
    except ValueError:
        return None


def detect_burst(entries, window_seconds=60, threshold=10):
    """Yield alerts when an IP reaches a request threshold."""
    windows = defaultdict(deque)
    alerted_ips = set()
    window_duration = timedelta(seconds=window_seconds)

    for entry in entries:
        ip = getattr(entry, "ip", None)
        if not ip:
            continue

        timestamp = parse_timestamp(
            getattr(entry, "timestamp", None)
        )
        if timestamp is None:
            continue

        ip_window = windows[ip]
        ip_window.append(timestamp)

        while (
            ip_window
            and timestamp - ip_window[0] > window_duration
        ):
            ip_window.popleft()

        if len(ip_window) >= threshold and ip not in alerted_ips:
            alerted_ips.add(ip)
            yield {
                "ip": ip,
                "count": len(ip_window),
                "window": window_seconds,
                "alert_type": "BURST",
            }


def correlate_events(entries):
    """Correlate scanner and SQLi events for each IP."""
    states = defaultdict(set)

    for entry in entries:
        ip = getattr(entry, "ip", None)
        if not ip:
            continue

        status = getattr(entry, "status", None)
        attack_type = getattr(entry, "attack_type", None)

        if str(status) == "404":
            states[ip].add("scanner")

        if attack_type == "SQLi":
            states[ip].add("sqli")

        if {"scanner", "sqli"}.issubset(states[ip]):
            yield {
                "ip": ip,
                "stages": ["scanner", "sqli"],
                "alert_type": "CRITICAL INCIDENT",
            }
            states[ip].clear()


def main():
    """Run the LogHunter analysis pipeline."""
    parser = argparse.ArgumentParser(
        description="Analyze Apache and Syslog files."
    )
    parser.add_argument("file", help="Path to the log file")
    args = parser.parse_args()

    entries = []

    for line in read_stream(args.file):
        entry = normalize_entry(line)
        if entry is not None:
            entries.append(entry)

    print(f"[*] Parsed entries: {len(entries)}")

    for entry in entries:
        enrich_ip(entry)
        analyze_user_agent(entry)
        check_threat_intel(entry)

    print("\n--- SQLi Detection ---")
    sqli_count = 0

    for entry in entries:
        detect_sqli(entry)
        if entry.attack_type == "SQLi":
            sqli_count += 1
            print(f"    {entry.ip}: SQLi detected")

    print(f"[*] SQLi entries: {sqli_count}")

    print("\n--- XSS Detection ---")
    xss_count = 0

    for entry in entries:
        detect_xss(entry)
        if entry.attack_type == "XSS":
            xss_count += 1
            print(f"    {entry.ip}: XSS detected")

    print(f"[*] XSS entries: {xss_count}")

    print("\n--- Brute Force ---")
    brute_force_alerts = list(detect_bruteforce(entries))
    print(f"[*] BRUTE_FORCE alerts: {len(brute_force_alerts)}")

    for alert in brute_force_alerts:
        print(
            f"    {alert['ip']}: "
            f"{alert['count']} failures"
        )

    print("\n--- Burst Detection ---")
    burst_alerts = list(detect_burst(entries))
    print(f"[*] BURST alerts: {len(burst_alerts)}")

    for alert in burst_alerts:
        print(
            f"    {alert['ip']}: "
            f"{alert['count']} requests in "
            f"{alert['window']}s window"
        )

    print("\n--- Correlation ---")

    # SQLi detection must run before event correlation.
    for entry in entries:
        detect_sqli(entry)

    incidents = list(correlate_events(entries))
    print("[*] CRITICAL INCIDENTS:")

    for incident in incidents:
        stages = " -> ".join(incident["stages"])
        print(f"    {incident['ip']}: {stages}")


if __name__ == "__main__":
    main()
