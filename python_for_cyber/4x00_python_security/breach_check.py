
#!/usr/bin/env python3
"""BreachCheck command-line entry point."""

import argparse
import sys


def read_file(filename: str) -> list:
    """Read a text file and return its lines as a list of strings."""
    try:
        with open(filename, "r", encoding="utf-8") as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filename}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied: {filename}", file=sys.stderr)
        sys.exit(1)


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

    if args.verbose:
        print(f"[INFO] Read {len(lines)} lines from {args.file}")


if __name__ == "__main__":
    main()
