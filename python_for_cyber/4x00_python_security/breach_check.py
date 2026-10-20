
#!/usr/bin/env python3
"""BreachCheck - command-line password policy auditing tool."""

import argparse
import logging
import re
import sys


LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
COMMON_PASSWORDS = {"password", "123456"}


def configure_logging() -> None:
    """Configure INFO logging to console and DEBUG logging to file."""
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT))

    file_handler = logging.FileHandler(
        "breach_check.log",
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)


def read_file(filename: str) -> list:
    """Read a text file and exit cleanly on common file errors."""
    try:
        with open(filename, "r", encoding="utf-8") as file:
            return file.readlines()
    except FileNotFoundError:
        logging.error("File not found: %s", filename)
        sys.exit(1)
    except PermissionError:
        logging.error("Permission denied: %s", filename)
        sys.exit(1)
    except IsADirectoryError:
        logging.error("Path is a directory, not a file: %s", filename)
        sys.exit(1)
    except UnicodeDecodeError:
        logging.error("File is not valid UTF-8 text: %s", filename)
        sys.exit(1)
    except OSError as error:
        logging.error("Unable to read file %s: %s", filename, error)
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


def validate_line(line: str) -> bool:
    """Check that a line follows the email:password format."""
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


def check_policy(password: str) -> str:
    """Return WEAK or COMPLIANT according to the password policy."""
    if (
        len(password) < 8
        or not any(character.isdigit() for character in password)
        or password.casefold() in COMMON_PASSWORDS
    ):
        return "WEAK"

    return "COMPLIANT"


def main() -> None:
    """Parse arguments and run the BreachCheck audit."""
    parser = argparse.ArgumentParser(
        description=(
            "BreachCheck - validate input records and audit "
            "password policy compliance."
        )
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
        help="enable verbose logging",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="path to the output report file",
    )

    args = parser.parse_args()
    configure_logging()

    logging.info("BreachCheck v1.0 startup...")
    logging.info("Processing file: %s", args.file)

    lines = read_file(args.file)
    cleaned_lines = clean_data(lines)

    valid_records = []
    invalid_count = 0

    for line_number, line in enumerate(cleaned_lines, start=1):
        logging.debug("Starting regex check on line %d...", line_number)

        if not validate_line(line):
            invalid_count += 1
            logging.debug("Line %d failed format validation", line_number)
            continue

        email, password = line.split(":", 1)
        status = check_policy(password)

        valid_records.append((email, status))

        logging.debug(
            "Line %d passed validation; policy status: %s",
            line_number,
            status,
        )

    weak_count = sum(
        1 for _, status in valid_records if status == "WEAK"
    )
    compliant_count = sum(
        1 for _, status in valid_records if status == "COMPLIANT"
    )

    logging.info("Processing complete.")
    logging.info("Input lines: %d", len(lines))
    logging.info("Clean lines: %d", len(cleaned_lines))
    logging.info("Invalid records: %d", invalid_count)
    logging.info("Valid records: %d", len(valid_records))
    logging.info("Weak passwords: %d", weak_count)
    logging.info("Compliant passwords: %d", compliant_count)

    if args.verbose:
        logging.info("Verbose mode enabled.")

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as report:
                report.write("BreachCheck v1.0 Report\n")
                report.write("======================\n")
                report.write(f"Input lines: {len(lines)}\n")
                report.write(f"Clean lines: {len(cleaned_lines)}\n")
                report.write(f"Invalid records: {invalid_count}\n")
                report.write(f"Valid records: {len(valid_records)}\n")
                report.write(f"Weak passwords: {weak_count}\n")
                report.write(f"Compliant passwords: {compliant_count}\n")

            logging.info("Report written to: %s", args.output)
        except OSError as error:
            logging.error("Unable to write report %s: %s", args.output, error)
            sys.exit(1)


if __name__ == "__main__":
    main()
