
#!/usr/bin/env python3
"""BreachCheck command-line entry point."""

import argparse
import logging
import re
import sys


LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"


def configure_logging() -> None:
    """Configure INFO logging to console and DEBUG logging to file."""
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT))

    file_handler = logging.FileHandler(
        "breach_check.log", encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)


def read_file(filename: str) -> list:
    """Read a file and handle common errors."""
    try:
        with open(filename, "r", encoding="utf-8") as file:
            lines = file.readlines()
        logging.debug("Successfully read input file: %s", filename)
        return lines
    except FileNotFoundError:
        logging.error("File not found: %s", filename)
        sys.exit(1)
    except PermissionError:
        logging.error("Permission denied: %s", filename)
        sys.exit(1)


def clean_data(lines: list) -> list:
    """Remove whitespace, blank lines, and comments."""
    cleaned_lines = []

    for line in lines:
        cleaned_line = line.strip()
        if not cleaned_line or cleaned_line.startswith("#"):
            continue
        cleaned_lines.append(cleaned_line)

    logging.debug(
        "Cleaned input: %d lines retained", len(cleaned_lines)
    )
    return cleaned_lines


def validate_line(line: str) -> bool:
    """Validate the email:password format."""
    match = re.fullmatch(r"([^:]+):([^:]+)", line)
    if match is None:
        return False

    email = match.group(1)
    email_pattern = (
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
        r"@"
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
    )
    return re.fullmatch(email_pattern, email) is not None


def main():
    """Parse arguments and run BreachCheck."""
    parser = argparse.ArgumentParser(
        description="BreachCheck - analyze an input file for potential breaches."
    )
    parser.add_argument(
        "-f", "--file", required=True, type=str,
        help="path to the input file to analyze (required)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="enable verbose output",
    )
    parser.add_argument(
        "-o", "--output", type=str,
        help="path to the output report file",
    )

    args = parser.parse_args()
    configure_logging()

    logging.info("BreachCheck v1.0 startup...")
    logging.info("Processing file: %s", args.file)

    lines = read_file(args.file)
    cleaned_lines = clean_data(lines)
    valid_lines = []

    for line_number, line in enumerate(cleaned_lines, start=1):
        logging.debug(
            "Starting regex check on line %d...", line_number
        )
        if validate_line(line):
            valid_lines.append(line)
        else:
            logging.debug(
                "Line %d failed format validation", line_number
            )

    logging.info(
        "Processing complete: %d valid lines", len(valid_lines)
    )

    if args.verbose:
        logging.info("Read %d lines from %s", len(lines), args.file)
        logging.info(
            "%d lines remain after cleaning", len(cleaned_lines)
        )


if __name__ == "__main__":
    main()
