from django.contrib import admin
from django.contrib.auth import get_user_model

from oauth2_provider.models import (
    get_access_token_admin_class,
    get_access_token_model,
    get_application_admin_class,
    get_application_model,
    get_grant_admin_class,
    get_grant_model,
    get_id_token_admin_class,
    get_id_token_model,
    get_refresh_token_admin_class,
    get_refresh_token_model,
)


has_email = hasattr(get_user_model(), "email")


# Only reveal a short suffix of a credential, and only when the value is long enough
# that the suffix is a small fraction of it. Shorter values are fully masked so a masked
# value never exposes most of a (potentially low-entropy) secret.
MASK_MIN_LENGTH = 16
MASK_SUFFIX_LENGTH = 4


def mask_credential(value):
    """
    Return a masked representation of a token/code that identifies a row in the
    admin without exposing the usable credential.

    Access/refresh tokens and authorization codes are stored in cleartext, so
    showing them verbatim (or making them searchable) would expose live,
    replayable credentials to any staff user with view access — and, for
    ``search_fields``, would leak them into the ``?q=`` query string captured by
    server access logs and browser history. Values shorter than
    ``MASK_MIN_LENGTH`` are fully masked; longer values reveal only their last
    ``MASK_SUFFIX_LENGTH`` characters, which is enough to correlate a row without
    meaningfully aiding a brute force of a high-entropy token.
    """
    if not value:
        return value
    if len(value) < MASK_MIN_LENGTH:
        return "…"
    return "…%s" % value[-MASK_SUFFIX_LENGTH:]


class ApplicationAdmin(admin.ModelAdmin):
    list_display = ("pk", "name", "user", "client_type", "authorization_grant_type")
    list_filter = ("client_type", "authorization_grant_type", "skip_authorization")
    radio_fields = {
        "client_type": admin.HORIZONTAL,
        "authorization_grant_type": admin.VERTICAL,
    }
    search_fields = ("name",) + (("user__email",) if has_email else ())
    raw_id_fields = ("user",)


class AccessTokenAdmin(admin.ModelAdmin):
    list_display = ("pk", "masked_token", "user", "application", "expires")
    list_select_related = ("application", "user")
    raw_id_fields = ("user", "source_refresh_token")
    # Search by non-secret identifiers only; never by the token itself.
    search_fields = ("application__client_id", "application__name") + (("user__email",) if has_email else ())
    list_filter = ("application",)
    # Keep the raw token off the change/view form; show a masked, read-only value instead.
    exclude = ("token",)
    readonly_fields = ("masked_token",)

    @admin.display(description="token")
    def masked_token(self, obj):
        return mask_credential(obj.token)


class GrantAdmin(admin.ModelAdmin):
    list_display = ("pk", "masked_code", "application", "user", "expires")
    raw_id_fields = ("user",)
    # Search by non-secret identifiers only; never by the authorization code itself.
    search_fields = ("application__client_id", "application__name") + (("user__email",) if has_email else ())
    # Keep the raw code off the change/view form; show a masked, read-only value instead.
    exclude = ("code",)
    readonly_fields = ("masked_code",)

    @admin.display(description="code")
    def masked_code(self, obj):
        return mask_credential(obj.code)


class IDTokenAdmin(admin.ModelAdmin):
    list_display = ("jti", "user", "application", "expires")
    raw_id_fields = ("user",)
    search_fields = ("user__email",) if has_email else ()
    list_filter = ("application",)
    list_select_related = ("application", "user")


class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ("pk", "masked_token", "user", "application")
    list_select_related = ("application", "user")
    raw_id_fields = ("user", "access_token")
    # Search by non-secret identifiers only; never by the token itself.
    search_fields = ("application__client_id", "application__name") + (("user__email",) if has_email else ())
    list_filter = ("application",)
    # Keep the raw token off the change/view form; show a masked, read-only value instead.
    exclude = ("token",)
    readonly_fields = ("masked_token",)

    @admin.display(description="token")
    def masked_token(self, obj):
        return mask_credential(obj.token)


application_model = get_application_model()
access_token_model = get_access_token_model()
grant_model = get_grant_model()
id_token_model = get_id_token_model()
refresh_token_model = get_refresh_token_model()

application_admin_class = get_application_admin_class()
access_token_admin_class = get_access_token_admin_class()
grant_admin_class = get_grant_admin_class()
id_token_admin_class = get_id_token_admin_class()
refresh_token_admin_class = get_refresh_token_admin_class()

admin.site.register(application_model, application_admin_class)
admin.site.register(access_token_model, access_token_admin_class)
admin.site.register(grant_model, grant_admin_class)
admin.site.register(id_token_model, id_token_admin_class)
admin.site.register(refresh_token_model, refresh_token_admin_class)
