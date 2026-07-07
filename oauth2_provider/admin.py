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


def mask_credential(value):
    """
    Return a masked representation of a token/code that identifies a row in the
    admin without exposing the usable credential.

    Access/refresh tokens and authorization codes are stored in cleartext, so
    showing them verbatim (or making them searchable) would expose live,
    replayable credentials to any staff user with view access — and, for
    ``search_fields``, would leak them into the ``?q=`` query string captured by
    server access logs and browser history. Only the last few characters are
    shown, which is enough to correlate a row without aiding a brute force.
    """
    if not value:
        return value
    if len(value) <= 6:
        return "…"
    return "…%s" % value[-6:]


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

    @admin.display(description="token")
    def masked_token(self, obj):
        return mask_credential(obj.token)


class GrantAdmin(admin.ModelAdmin):
    list_display = ("pk", "masked_code", "application", "user", "expires")
    raw_id_fields = ("user",)
    # Search by non-secret identifiers only; never by the authorization code itself.
    search_fields = ("application__client_id", "application__name") + (("user__email",) if has_email else ())

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
