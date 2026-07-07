"""
Tests for the default admin classes, ensuring that cleartext bearer tokens and
authorization codes are never exposed verbatim (in ``list_display``) nor made
searchable (in ``search_fields``, which would leak them into the ``?q=`` query
string and therefore into access logs / browser history).
"""

from oauth2_provider.admin import (
    AccessTokenAdmin,
    GrantAdmin,
    RefreshTokenAdmin,
    mask_credential,
)


def test_mask_credential_hides_the_secret():
    # A long value reveals only its last few characters.
    assert mask_credential("abcdef1234567890") == "…7890"
    # Short/empty values are fully masked and reveal nothing.
    assert mask_credential("short") == "…"
    assert mask_credential("") == ""
    assert mask_credential(None) is None
    # Boundary: a value just over the old 6-char threshold must not reveal most of itself.
    assert mask_credential("abcdefg") == "…"
    # Boundary: just below the minimum reveal length is still fully masked.
    assert mask_credential("a" * 15) == "…"
    # At the minimum length only the last few characters are shown.
    assert mask_credential("b" * 16) == "…bbbb"
    # The full secret is never returned, regardless of length.
    for secret in ("abcdefg", "supersecrettokenvalue", "x" * 40):
        assert secret not in mask_credential(secret)


def test_access_token_admin_does_not_expose_token():
    assert "token" not in AccessTokenAdmin.list_display
    assert "token" not in AccessTokenAdmin.search_fields
    # Search stays available by non-secret application identifiers.
    assert "application__client_id" in AccessTokenAdmin.search_fields
    assert "application__name" in AccessTokenAdmin.search_fields


def test_refresh_token_admin_does_not_expose_token():
    assert "token" not in RefreshTokenAdmin.list_display
    assert "token" not in RefreshTokenAdmin.search_fields
    assert "application__client_id" in RefreshTokenAdmin.search_fields
    assert "application__name" in RefreshTokenAdmin.search_fields


def test_grant_admin_does_not_expose_code():
    assert "code" not in GrantAdmin.list_display
    assert "code" not in GrantAdmin.search_fields
    assert "application__client_id" in GrantAdmin.search_fields
    assert "application__name" in GrantAdmin.search_fields
