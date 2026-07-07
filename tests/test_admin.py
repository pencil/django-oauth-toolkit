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
    assert mask_credential("abcdef1234567890") == "…567890"
    # Short/empty values do not reveal anything useful.
    assert mask_credential("short") == "…"
    assert mask_credential("") == ""
    assert mask_credential(None) is None
    # The full secret is never returned.
    secret = "supersecrettokenvalue"
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
