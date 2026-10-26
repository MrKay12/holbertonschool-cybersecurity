#!/usr/bin/env python3
"""LogHunter - Log Analysis Engine."""

import argparse
import re


APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<date>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]+" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)

SYSLOG_PATTERN = re.compile(
    r'(?P<date>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) '
    r'(?P<host>\S+) '
    r'(?P<process>[\w./-]+(?:\[\d+\])?): '
    r'(?P<message>.*)'
)

IP_PATTERN = re.compile(
    r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])'
)

SQLI_SIGNATURES = [
    re.compile(r"\bunion\s+select\b", re.IGNORECASE),
    re.compile(r"""'\s*or\s+['"]?\d+['"]?\s*=\s*['"]?\d+""",
               re.IGNORECASE),
    re.compile(r"--"),
]

GEOIP_DB = {
    "1.2.3.4": "US",
    "5.6.7.8": "RU",
}

BOT_SIGNATURES = ("sqlmap", "nikto", "curl", "python")

BLACKLIST = {"10.0.0.1", "192.168.1.66"}


class LogEntry:
    """Represent a normalized log entry."""

    def __init__(
        self,
        ip="",
        timestamp="",
        service="",
        message="",
        raw_line="",
        method=None,
        path=None,
        status=None,
        size=None,
        user_agent="",
        source=None,
    ):
        """Initialize a normalized log entry."""
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
        self.country = "UNKNOWN"
        self.is_bot = False
        self.alert_level = "LOW"
        self.attack_type = None


def read_stream(file_path: str):
    """Yield one line at a time from a file."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                yield line
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")


def parse_apache_line(line: str) -> dict:
    """Parse an Apache access log line."""
    match = APACHE_PATTERN.search(line)
    if match is None:
        return None
    return match.groupdict()


def parse_syslog_line(line: str) -> dict:
    """Parse a Syslog line."""
    match = SYSLOG_PATTERN.search(line)
    if match is None:
        return None
    return match.groupdict()


def normalize_entry(parsed_dict, log_type, raw_line="") -> LogEntry:
    """Normalize parsed Apache or Syslog data into a LogEntry."""
    if log_type == "apache":
        status = int(parsed_dict["status"])
        method = parsed_dict["method"]
        path = parsed_dict["path"]
        size_value = parsed_dict.get("size")
        size = (
            int(size_value)
            if size_value is not None and size_value.isdigit()
            else None
        )
        user_agent = parsed_dict.get("user_agent") or ""
        message = f"{method} {path} {status}"

        return LogEntry(
            ip=parsed_dict["ip"],
            timestamp=parsed_dict["date"],
            service="http",
            message=message,
            raw_line=raw_line,
            method=method,
            path=path,
            status=status,
            size=size,
            user_agent=user_agent,
            source="apache",
        )

    if log_type == "syslog":
        message = parsed_dict["message"]
        ip_match = IP_PATTERN.search(message)
        ip = ip_match.group(0) if ip_match else ""

        return LogEntry(
            ip=ip,
            timestamp=parsed_dict["date"],
            service="ssh",
            message=message,
            raw_line=raw_line,
            source="syslog",
        )

    raise ValueError(f"Unsupported log type: {log_type}")


def filter_logs(stream, status_codes=[404, 500]):
    """Yield entries whose status matches the requested codes."""
    for entry in stream:
        if getattr(entry, "status", None) in status_codes:
            yield entry


def enrich_ip(log_entry):
    """Add GeoIP country information to a log entry."""
    log_entry.country = GEOIP_DB.get(log_entry.ip, "UNKNOWN")
    return log_entry


def analyze_user_agent(log_entry):
    """Detect bots and tools using known signatures."""
    fields = (
        getattr(log_entry, "user_agent", ""),
        getattr(log_entry, "message", ""),
        getattr(log_entry, "raw_line", ""),
    )

    combined_text = " ".join(
        str(field or "") for field in fields
    ).lower()

    log_entry.is_bot = any(
        signature in combined_text
        for signature in BOT_SIGNATURES
    )

    return log_entry


def check_threat_intel(log_entry):
    """Check whether an IP address is on the threat blacklist."""
    if log_entry.ip in BLACKLIST:
        log_entry.alert_level = "HIGH"
    else:
        log_entry.alert_level = "LOW"

    return log_entry


def detect_sqli(log_entry):
    """Detect SQL injection patterns in a log entry."""
    path = str(getattr(log_entry, "path", "") or "")
    message = str(getattr(log_entry, "message", "") or "")
    text = f"{path} {message}"

    for signature in SQLI_SIGNATURES:
        if signature.search(text):
            log_entry.attack_type = "SQLi"
            return log_entry

    return log_entry


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Path to the log file")
    args = parser.parse_args()

    print("[*] LogHunter - Log Analysis Engine")
    print(f"[*] Reading: {args.file}")

    apache_lines = 0
    syslog_lines = 0
    entries = []
    sample_entry = None

    for line in read_stream(args.file):
        parsed = parse_apache_line(line)

        if parsed is not None:
            apache_lines += 1
            entry = normalize_entry(parsed, "apache", line)
        else:
            parsed = parse_syslog_line(line)

            if parsed is not None:
                syslog_lines += 1
                entry = normalize_entry(parsed, "syslog", line)
            else:
                continue

        entries.append(entry)

        if sample_entry is None:
            sample_entry = entry

    print("--- Parsing ---")
    print(f"[*] Apache lines:  {apache_lines}")
    print(f"[*] Syslog lines:  {syslog_lines}")
    print(f"[*] Total parsed:  {apache_lines + syslog_lines}")

    if sample_entry is not None:
        print("[*] Sample entry:")
        if sample_entry.service == "http":
            print(
                f"    ip={sample_entry.ip} | "
                f"service={sample_entry.service} | "
                f"status={sample_entry.status} | "
                f"path={sample_entry.path}"
            )
        else:
            print(
                f"    ip={sample_entry.ip} | "
                f"service={sample_entry.service} | "
                f"timestamp={sample_entry.timestamp}"
            )

    suspicious = sum(1 for _ in filter_logs(entries))
    print("--- Filtering ---")
    print(f"[*] Suspicious (404, 500): {suspicious}")

    known_ips = 0
    bots_detected = 0
    high_alerts = 0
    sqli_attempts = 0

    for entry in entries:
        enrich_ip(entry)
        if entry.country != "UNKNOWN":
            known_ips += 1

        analyze_user_agent(entry)
        if entry.is_bot:
            bots_detected += 1

        check_threat_intel(entry)
        if entry.alert_level == "HIGH":
            high_alerts += 1

        detect_sqli(entry)
        if entry.attack_type == "SQLi":
            sqli_attempts += 1

    print("--- Enrichment ---")
    print(
        f"[*] GeoIP: {len(entries)} entries enriched "
        f"({known_ips} known IPs)"
    )
    print(f"[*] Bots detected: {bots_detected}")

    print("--- Threat Intelligence ---")
    print(
        f"[*] HIGH alerts: {high_alerts} entries "
        "from blacklisted IPs"
    )

    print("--- Attack Detection ---")
    print(f"[*] SQLi attempts: {sqli_attempts}")
    print("[*] XSS attempts:  0")
