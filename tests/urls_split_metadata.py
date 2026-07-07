from django.urls import include, path

from oauth2_provider.urls import (
    base_urlpatterns,
    management_urlpatterns,
    metadata_urlpatterns,
    oidc_urlpatterns,
)


# The documented RFC 8414 deployment: the metadata endpoint at the server root
# and the rest of the toolkit under an "/o/" prefix.
urlpatterns = [
    # Distinct instance namespace so reverse("oauth2_provider:...") for the
    # endpoints below resolves unambiguously to the "/o/" mount.
    path("", include((metadata_urlpatterns, "oauth2_provider"), namespace="oauth2_metadata")),
    path(
        "o/",
        include((base_urlpatterns + management_urlpatterns + oidc_urlpatterns, "oauth2_provider")),
    ),
]
