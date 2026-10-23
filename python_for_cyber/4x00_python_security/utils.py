
#!/usr/bin/env python3
"""Utility functions for cleaning, validating, and hashing BreachCheck data."""

import hashlib
import logging
import re


def clean_data(lines: list) -> list:
    """Strip surrounding whitespace and discard blank lines and comments."""
    cleaned_lines = []

    for line in lines:
        cleaned_line = line.strip()

        if not cleaned_line or cleaned_line.startswith("#"):
            continue

        cleaned_lines.append(cleaned_line)

    logging.debug("Cleaned input: %d lines retained", len(cleaned_lines))
    return cleaned_lines


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
