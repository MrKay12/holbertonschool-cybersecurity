#!/usr/bin/env python3
"""LogHunter - Log Analysis Engine."""

import argparse
import re


APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<date>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]+" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
)


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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Path to the log file")
    args = parser.parse_args()

    print("[*] LogHunter - Log Analysis Engine")
    print(f"[*] Reading: {args.file}")

    apache_lines = 0
    syslog_lines = 0

    for line in read_stream(args.file):
        if parse_apache_line(line) is not None:
            apache_lines += 1

    print("--- Parsing ---")
    print(f"[*] Apache lines:  {apache_lines}")
    print(f"[*] Syslog lines:  {syslog_lines}")
    print(f"[*] Total parsed:  {apache_lines + syslog_lines}")
