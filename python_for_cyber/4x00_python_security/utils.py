#!/usr/bin/env python3
"""Utility functions for cleaning, validating, and hashing BreachCheck data."""

import hashlib
import logging
import re
from typing import Iterable, Iterator


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