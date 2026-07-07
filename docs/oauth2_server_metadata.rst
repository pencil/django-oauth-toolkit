OAuth 2.0 Authorization Server Metadata
========================================

Django OAuth Toolkit provides an authorization server metadata endpoint based on
`RFC 8414 <https://www.rfc-editor.org/rfc/rfc8414>`_. This allows OAuth 2.0 clients
to discover the server's capabilities and endpoint locations automatically, without
requiring OIDC to be enabled.

URL Configuration
-----------------

RFC 8414 requires the metadata endpoint to be at
``{issuer}/.well-known/oauth-authorization-server``. Since the issuer is typically the
server's root URL (e.g., ``https://example.com``), the metadata endpoint **must be
mounted at the root**, not under a prefix like ``/o/``.

The metadata view is provided in a separate ``metadata_urlpatterns`` list for this
reason. If you mount the rest of the toolkit at a prefix, mount the metadata view at
the root separately:

.. code-block:: python

    from oauth2_provider.urls import (
        base_urlpatterns,
        management_urlpatterns,
        metadata_urlpatterns,
        oidc_urlpatterns,
    )

    urlpatterns = [
        # Metadata at root (RFC 8414 requirement). Give this include a distinct
        # instance namespace so the prefixed mount below stays the unambiguous
        # "oauth2_provider" namespace that endpoint reversing relies on.
        path(
            "",
            include((metadata_urlpatterns, "oauth2_provider"), namespace="oauth2_metadata"),
        ),
        # The rest of the toolkit under your chosen prefix
        path(
            "o/",
            include(
                (base_urlpatterns + management_urlpatterns + oidc_urlpatterns, "oauth2_provider")
            ),
        ),
    ]

If you use ``include("oauth2_provider.urls")`` without a prefix, everything works
out of the box — ``metadata_urlpatterns`` is included in the default ``urlpatterns``.

Example response::

    HTTP/1.1 200 OK
    Content-Type: application/json
    Access-Control-Allow-Origin: *

    {
      "issuer": "https://example.com",
      "authorization_endpoint": "https://example.com/o/authorize/",
      "token_endpoint": "https://example.com/o/token/",
      "revocation_endpoint": "https://example.com/o/revoke_token/",
      "introspection_endpoint": "https://example.com/o/introspect/",
      "jwks_uri": "https://example.com/o/.well-known/jwks.json",
      "response_types_supported": ["code", "token"],
      "grant_types_supported": [
        "authorization_code",
        "implicit",
        "password",
        "client_credentials",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:device_code"
      ],
      "scopes_supported": ["read", "write"],
      "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic"
      ],
      "revocation_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic"
      ],
      "introspection_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic"
      ],
      "code_challenge_methods_supported": ["plain", "S256"]
    }

``jwks_uri`` is only included when OIDC is enabled and an RSA private key is
configured (see :ref:`OIDC_RSA_PRIVATE_KEY <oidc-rsa-private-key>`). When OIDC
is disabled, ``jwks_uri`` is omitted since the JWKS endpoint is not reachable.

The issuer URL is derived from the incoming request by default: it is the request
URL with the ``/.well-known/oauth-authorization-server`` suffix stripped, so any
mount prefix is preserved. To set it explicitly, configure ``OIDC_ISS_ENDPOINT``
in your ``OAUTH2_PROVIDER`` settings (see :doc:`settings`).

The ``revocation_endpoint_auth_methods_supported`` and
``introspection_endpoint_auth_methods_supported`` fields are only included when the
respective endpoints are registered, and reuse the
``token_endpoint_auth_methods_supported`` value.

The response fields ``response_types_supported``, ``grant_types_supported``, and
``token_endpoint_auth_methods_supported`` can be customised via settings — see
:doc:`settings` for details.
