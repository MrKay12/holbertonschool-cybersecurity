
#!/usr/bin/env python3
"""BreachCheck command-line entry point."""

import argparse
import sys


def read_file(filename: str) -> list:
    """Read a text file and handle common file errors."""
    try:
        with open(filename, "r", encoding="utf-8") as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filename}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied: {filename}", file=sys.stderr)
        sys.exit(1)


def clean_data(lines: list) -> list:
    """Strip surrounding whitespace and discard blank lines and comments."""
    cleaned_lines = []

    for line in lines:
        cleaned_line = line.strip()

        if not cleaned_line or cleaned_line.startswith("#"):
            continue

        cleaned_lines.append(cleaned_line)

    return cleaned_lines


def main():
    """Parse command-line arguments and start BreachCheck."""
    parser = argparse.ArgumentParser(
        description="BreachCheck - analyze an input file for potential breaches."
    )
    parser.add_argument(
        "-f",
        "--file",
        required=True,
        type=str,
        help="path to the input file to analyze (required)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable verbose output",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="path to the output report file",
    )

    args = parser.parse_args()

    print("BreachCheck v1.0 startup...")
    lines = read_file(args.file)
    cleaned_lines = clean_data(lines)

    if args.verbose:
        print(f"[INFO] Read {len(lines)} lines from {args.file}")
        print(f"[INFO] {len(cleaned_lines)} lines remain after cleaning")


if __name__ == "__main__":
    main()
