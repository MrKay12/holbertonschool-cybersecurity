#!/usr/bin/env python3
"""Utility functions for cleaning, validating, and hashing BreachCheck data."""

import hashlib
import logging
import re
from typing import Iterable, Iterator


def read_file(filename: str) -> Iterator[str]:
    """Yield file lines one at a time using a context manager."""
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


def clean_data(lines: Iterable[str]) -> Iterator[str]:
    """Yield nonblank, non-comment lines after stripping whitespace."""
    cleaned_count = 0

    for line in lines:
        cleaned_line = line.strip()

        if not cleaned_line or cleaned_line.startswith("#"):
            continue

        cleaned_count += 1
        yield cleaned_line

    logging.debug("Cleaned input: %d lines retained", cleaned_count)


def validate_line(line: str) -> bool:
    """Return True if line matches email:password with a plausible email."""
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


def hash_password(password: str, salt: str) -> str:
    """Return the SHA-256 hex digest of the UTF-8 password followed by salt."""
    password_and_salt = password.encode("utf-8") + salt.encode("utf-8")
    return hashlib.sha256(password_and_salt).hexdigest()