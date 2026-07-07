"""
Tests for the default admin classes, ensuring that cleartext bearer tokens and
authorization codes are never exposed verbatim (in ``list_display``, in the
change/view form, or via ``__str__``) nor made searchable (in ``search_fields``,
which would leak them into the ``?q=`` query string and therefore into access
logs / browser history).
"""

from django.contrib.admin.sites import AdminSite
from django.test import RequestFactory

from oauth2_provider.admin import (
    AccessTokenAdmin,
    GrantAdmin,
    RefreshTokenAdmin,
    mask_credential,
)
from oauth2_provider.models import (
    get_access_token_model,
    get_grant_model,
    get_refresh_token_model,
)


def _admin_form_fields(admin_class, model):
    """Return the fields the admin change/view form would render."""
    request = RequestFactory().get("/")
    model_admin = admin_class(model, AdminSite())
    return list(model_admin.get_form(request).base_fields)


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
    # The raw token is not rendered on the change/view form (a masked value is shown).
    assert "token" not in _admin_form_fields(AccessTokenAdmin, get_access_token_model())
    assert "masked_token" in AccessTokenAdmin.readonly_fields


def test_refresh_token_admin_does_not_expose_token():
    assert "token" not in RefreshTokenAdmin.list_display
    assert "token" not in RefreshTokenAdmin.search_fields
    assert "application__client_id" in RefreshTokenAdmin.search_fields
    assert "application__name" in RefreshTokenAdmin.search_fields
    assert "token" not in _admin_form_fields(RefreshTokenAdmin, get_refresh_token_model())
    assert "masked_token" in RefreshTokenAdmin.readonly_fields


def test_grant_admin_does_not_expose_code():
    assert "code" not in GrantAdmin.list_display
    assert "code" not in GrantAdmin.search_fields
    assert "application__client_id" in GrantAdmin.search_fields
    assert "application__name" in GrantAdmin.search_fields
    assert "code" not in _admin_form_fields(GrantAdmin, get_grant_model())
    assert "masked_code" in GrantAdmin.readonly_fields
