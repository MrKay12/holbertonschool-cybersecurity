#!/usr/bin/env python3
"""Unit tests for the BreachCheck security auditing tool."""

import unittest

import breach_check
from utils import hash_password, validate_line


class TestValidateLine(unittest.TestCase):
    """Tests for input record validation."""

    def test_valid_email_password(self):
        """Accept a correctly formatted email:password record."""
        self.assertTrue(validate_line("user@example.com:MyPass123"))

    def test_invalid_email_format(self):
        """Reject a record containing an invalid email address."""
        self.assertFalse(validate_line("invalid-email:MyPass123"))

    def test_invalid_record_format(self):
        """Reject a record without the required separator."""
        self.assertFalse(validate_line("user@example.comMyPass123"))

    def test_missing_email(self):
        """Reject a record with a missing email."""
        self.assertFalse(validate_line(":MyPass123"))

    def test_missing_password(self):
        """Reject a record with a missing password."""
        self.assertFalse(validate_line("user@example.com:"))


class TestCheckPolicy(unittest.TestCase):
    """Tests for password policy validation."""

    @classmethod
    def setUpClass(cls):
        """Configure a predictable password policy for the tests."""
        breach_check.MIN_LENGTH = 8
        breach_check.COMMON_PASSWORDS = {"password", "123456"}
        breach_check.CONFIG_SALT = "TestSalt"

    def test_short_password(self):
        """Mark a password shorter than the minimum length as weak."""
        self.assertEqual(breach_check.check_policy("Ab1"), "WEAK")

    def test_common_numeric_password(self):
        """Mark a common numeric password as weak."""
        self.assertEqual(breach_check.check_policy("123456"), "WEAK")

    def test_compliant_password(self):
        """Accept a sufficiently long password containing a digit."""
        self.assertEqual(
            breach_check.check_policy("SecurePass123"),
            "COMPLIANT",
        )


class TestHashPassword(unittest.TestCase):
    """Tests for password hashing."""

    def test_same_input_produces_same_hash(self):
        """Verify identical password and salt produce identical hashes."""
        password = "SecurePass123"
        salt = "TestSalt"

        first_hash = hash_password(password, salt)
        second_hash = hash_password(password, salt)

        self.assertEqual(first_hash, second_hash)

    def test_hash_is_sha256_hex_digest(self):
        """Verify the hash is a 64-character hexadecimal SHA-256 digest."""
        result = hash_password("SecurePass123", "TestSalt")

        self.assertEqual(len(result), 64)
        self.assertRegex(result, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()