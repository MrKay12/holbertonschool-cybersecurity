
#!/usr/bin/env python3
"""BreachCheck - command-line password policy auditing tool."""

import argparse
import hashlib
import logging
import re
import secrets
import sys


LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
COMMON_PASSWORDS = {"password", "123456"}


def configure_logging() -> None:
    """Configure INFO logging to the console and DEBUG logging to a file."""
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
    except (OSError, UnicodeDecodeError) as error:
        logging.error("Unable to read file %s: %s", filename, error)
        sys.exit(1)


def clean_data(lines: list) -> list:
    """Remove surrounding whitespace, blank lines, and comments."""
    cleaned_lines = []

    for line in lines:
        cleaned_line = line.strip()
        if not cleaned_line or cleaned_line.startswith("#"):
            continue
        cleaned_lines.append(cleaned_line)

    logging.debug("Cleaned input: %d lines retained", len(cleaned_lines))
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


def check_policy(password: str) -> str:
    """Return WEAK or COMPLIANT according to the password policy."""
    if (
        len(password) < 8
        or not any(character.isdigit() for character in password)
        or password.casefold() in COMMON_PASSWORDS
    ):
        return "WEAK"

    return "COMPLIANT"


def hash_password(password: str, salt: str) -> str:
    """Hash a password and salt using SHA-256."""
    password_and_salt = password.encode("utf-8") + salt.encode("utf-8")
    return hashlib.sha256(password_and_salt).hexdigest()


def main() -> None:
    """Parse arguments and run the BreachCheck audit."""
    parser = argparse.ArgumentParser(
        description="BreachCheck - validate records and audit password policy."
    )
    parser.add_argument(
        "-f", "--file", required=True,
        help="path to the input file to analyze",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="enable verbose logging",
    )
    parser.add_argument(
        "-o", "--output",
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

        # Use a distinct random salt for each password.
        salt = secrets.token_hex(16)
        password_hash = hash_password(password, salt)

        valid_records.append({
            "email": email,
            "salt": salt,
            "password_hash": password_hash,
            "status": status,
        })

        logging.debug(
            "Line %d passed validation; policy status: %s",
            line_number,
            status,
        )

    weak_count = sum(
        record["status"] == "WEAK" for record in valid_records
    )
    compliant_count = sum(
        record["status"] == "COMPLIANT" for record in valid_records
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
                report.write(
                    "\nHashed records (email | salt | SHA-256 | policy)\n"
                )

                for record in valid_records:
                    report.write(
                        f"{record['email']} | {record['salt']} | "
                        f"{record['password_hash']} | {record['status']}\n"
                    )

            logging.info("Report written to: %s", args.output)

        except OSError as error:
            logging.error(
                "Unable to write report %s: %s", args.output, error
            )
            sys.exit(1)


if __name__ == "__main__":
    main()
