#!/usr/bin/env python3
"""BreachCheck - command-line password policy auditing tool."""

import argparse
import configparser
import logging
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Iterator, Union

from utils import clean_data, hash_password, validate_line

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
CONFIG_PATH = Path(__file__).resolve().with_name("config.ini")
MIN_LENGTH = None
COMMON_PASSWORDS = set()
CONFIG_SALT = None


def configure_logging() -> None:
    """Configure INFO logging to the console and DEBUG logging to a file."""
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT))

    file_handler = logging.FileHandler("breach_check.log", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)


def load_config(
    filename: Union[str, Path] = CONFIG_PATH,
) -> configparser.ConfigParser:
    """Load configuration and populate security policy settings."""
    global MIN_LENGTH, COMMON_PASSWORDS, CONFIG_SALT

    config = configparser.ConfigParser()
    config_path = Path(filename)

    if not config_path.is_file():
        print("[ERROR] config file missing", file=sys.stderr)
        raise SystemExit(1)

    try:
        with config_path.open("r", encoding="utf-8") as config_file:
            config.read_file(config_file)

        security = config["SECURITY"]
        CONFIG_SALT = security.get("Salt", "").strip()
        MIN_LENGTH = security.getint("MinLength")
        common_list = security.get("CommonList", "password,123456")

        COMMON_PASSWORDS = {
            item.strip().casefold()
            for item in common_list.split(",")
            if item.strip()
        }

        if not CONFIG_SALT:
            raise ValueError("SECURITY.Salt must not be empty")

        if MIN_LENGTH < 1:
            raise ValueError("SECURITY.MinLength must be greater than zero")

    except (configparser.Error, KeyError, ValueError, OSError) as error:
        print(f"[ERROR] Invalid config file: {error}", file=sys.stderr)
        raise SystemExit(1) from error

    return config


def read_file(filename: str) -> Iterator[str]:
    """Yield input lines one at a time and handle common file errors."""
    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                yield line

        logging.debug("Successfully read input file: %s", filename)

    except FileNotFoundError:
        logging.error("File not found: %s", filename)
        raise SystemExit(1)

    except PermissionError:
        logging.error("Permission denied: %s", filename)
        raise SystemExit(1)

    except IsADirectoryError:
        logging.error("Path is a directory, not a file: %s", filename)
        raise SystemExit(1)

    except (OSError, UnicodeDecodeError) as error:
        logging.error("Unable to read file %s: %s", filename, error)
        raise SystemExit(1) from error


def check_policy(password: str) -> str:
    """Return WEAK or COMPLIANT using the loaded configuration policy."""
    if MIN_LENGTH is None:
        load_config()

    if (
        len(password) < MIN_LENGTH
        or not any(character.isdigit() for character in password)
        or password.casefold() in COMMON_PASSWORDS
    ):
        return "WEAK"

    return "COMPLIANT"


def main() -> None:
    """Parse arguments and run the BreachCheck audit."""
    parser = argparse.ArgumentParser(
        description=(
            "BreachCheck - validate input records and audit password policy."
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
    load_config()

    logging.info("BreachCheck v1.0 startup...")
    logging.info("Processing file: %s", args.file)

    input_lines = 0
    clean_lines = 0
    invalid_count = 0
    valid_count = 0
    weak_count = 0
    compliant_count = 0

    with tempfile.TemporaryFile(
        mode="w+t",
        encoding="utf-8",
    ) as records_file:

        def counted_lines() -> Iterator[str]:
            nonlocal input_lines

            for raw_line in read_file(args.file):
                input_lines += 1
                yield raw_line

        for line_number, line in enumerate(
            clean_data(counted_lines()),
            start=1,
        ):
            clean_lines += 1

            logging.debug(
                "Starting regex check on line %d...",
                line_number,
            )

            if not validate_line(line):
                invalid_count += 1

                logging.debug(
                    "Line %d failed format validation",
                    line_number,
                )
                continue

            email, password = line.split(":", 1)
            status = check_policy(password)
            salt = f"{CONFIG_SALT}{secrets.token_hex(16)}"
            password_hash = hash_password(password, salt)

            valid_count += 1

            if status == "WEAK":
                weak_count += 1
            else:
                compliant_count += 1

            records_file.write(
                f"{email} | {salt} | {password_hash} | {status}\n"
            )

            logging.debug(
                "Line %d passed validation; policy status: %s",
                line_number,
                status,
            )

        logging.info("Processing complete.")
        logging.info("Input lines: %d", input_lines)
        logging.info("Clean lines: %d", clean_lines)
        logging.info("Invalid records: %d", invalid_count)
        logging.info("Valid records: %d", valid_count)
        logging.info("Weak passwords: %d", weak_count)
        logging.info("Compliant passwords: %d", compliant_count)

        if args.output:
            try:
                with open(
                    args.output,
                    "w",
                    encoding="utf-8",
                ) as report:
                    report.write("BreachCheck v1.0 Report\n")
                    report.write("======================\n")
                    report.write(f"Input lines: {input_lines}\n")
                    report.write(f"Clean lines: {clean_lines}\n")
                    report.write(f"Invalid records: {invalid_count}\n")
                    report.write(f"Valid records: {valid_count}\n")
                    report.write(f"Weak passwords: {weak_count}\n")
                    report.write(
                        f"Compliant passwords: {compliant_count}\n"
                    )
                    report.write(
                        "\nHashed records (email | salt | SHA-256 | policy)\n"
                    )

                    records_file.seek(0)

                    for record_line in records_file:
                        report.write(record_line)

                logging.info("Report written to: %s", args.output)

            except OSError as error:
                logging.error(
                    "Unable to write report %s: %s",
                    args.output,
                    error,
                )
                raise SystemExit(1) from error

    if args.verbose:
        logging.info("Verbose mode enabled.")


if __name__ == "__main__":
    main()