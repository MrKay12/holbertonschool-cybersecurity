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
        user_agent="",
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
        self.user_agent = user_agent


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
    match = re.search(APACHE_PATTERN, line)
    if match is None:
        return None
    return match.groupdict()


def parse_syslog_line(line: str) -> dict:
    """Parse a Syslog line."""
    match = re.search(SYSLOG_PATTERN, line)
    if match is None:
        return None
    return match.groupdict()


def normalize_entry(parsed_dict, log_type, raw_line="") -> LogEntry:
    """Normalize parsed Apache or Syslog data into a LogEntry."""
    if log_type == "apache":
        status = int(parsed_dict["status"])
        method = parsed_dict["method"]
        path = parsed_dict["path"]
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
            user_agent=user_agent,
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
        )

    raise ValueError(f"Unsupported log type: {log_type}")


def filter_logs(stream, status_codes=[404, 500]):
    """Yield entries whose status matches one of the requested codes."""
    for entry in stream:
        if getattr(entry, "status", None) in status_codes:
            yield entry


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
            apache_lines
