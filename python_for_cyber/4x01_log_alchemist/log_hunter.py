#!/usr/bin/env python3
"""LogHunter - Log Analysis Engine."""

import argparse


def read_stream(file_path: str):
    """Yield one line at a time from a file."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                yield line
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Path to the log file")
    args = parser.parse_args()

    print("[*] LogHunter - Log Analysis Engine")
    print(f"[*] Reading: {args.file}")

    lines_read = 0

    for _ in read_stream(args.file):
        lines_read += 1

    if lines_read == 0:
        print("[!] No data to process. Exiting.")
    else:
        print(f"[*] Lines read: {lines_read}")
