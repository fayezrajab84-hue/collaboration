"""
Unit tests for form-walk safety heuristics (no browser).

Exercises the regex-based guards — the actual DOM interaction is covered
by integration tests against a known fixture page.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crawler.forms import (  # noqa: E402
    _DESTRUCTIVE_TEXT,
    _FILL_BY_TYPE,
    _FORBIDDEN_INPUT_TYPES,
    _FORBIDDEN_NAME_PATTERNS,
)


class TestDestructiveText:
    def test_delete(self):
        assert _DESTRUCTIVE_TEXT.search("Delete account")

    def test_pay(self):
        assert _DESTRUCTIVE_TEXT.search("Pay now")

    def test_checkout(self):
        assert _DESTRUCTIVE_TEXT.search("Proceed to checkout")

    def test_confirm(self):
        assert _DESTRUCTIVE_TEXT.search("Confirm transfer")

    def test_transfer(self):
        assert _DESTRUCTIVE_TEXT.search("transfer funds")

    def test_unsubscribe(self):
        assert _DESTRUCTIVE_TEXT.search("Unsubscribe from list")

    def test_safe_text_not_flagged(self):
        assert not _DESTRUCTIVE_TEXT.search("Search")
        assert not _DESTRUCTIVE_TEXT.search("Submit")
        assert not _DESTRUCTIVE_TEXT.search("Apply filter")


class TestForbiddenInputs:
    def test_password_type_blocked(self):
        assert "password" in _FORBIDDEN_INPUT_TYPES

    def test_file_type_blocked(self):
        assert "file" in _FORBIDDEN_INPUT_TYPES


class TestForbiddenNames:
    def test_card_fields_blocked(self):
        pat = _FORBIDDEN_NAME_PATTERNS[0]
        assert pat.search("card_number")
        assert pat.search("creditCard")
        assert pat.search("cvv")
        assert pat.search("ssn")
        assert pat.search("iban")
        assert pat.search("otp_code")

    def test_normal_fields_allowed(self):
        pat = _FORBIDDEN_NAME_PATTERNS[0]
        assert not pat.search("email")
        assert not pat.search("username")
        assert not pat.search("search_query")


class TestFillByType:
    def test_email_placeholder_is_valid_format(self):
        assert "@" in _FILL_BY_TYPE["email"]

    def test_tel_has_digits(self):
        assert any(c.isdigit() for c in _FILL_BY_TYPE["tel"])

    def test_all_values_are_strings(self):
        for v in _FILL_BY_TYPE.values():
            assert isinstance(v, str)
            assert len(v) > 0
