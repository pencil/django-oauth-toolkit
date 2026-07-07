import pytest

from oauth2_provider import utils


def test_jwk_from_pem_caches_jwk():
    a_tiny_rsa_key = """-----BEGIN RSA PRIVATE KEY-----
MGQCAQACEQCxqYaL6GtPooVMhVwcZrCfAgMBAAECECyNmdsuHvMqIEl9/Fex27kC
CQDlc0deuSVrtQIJAMY4MTw2eCeDAgkA5VzfMykQ5yECCQCgkF4Zl0nHPwIJALPv
+IAFUPv3
-----END RSA PRIVATE KEY-----"""

    # For the same private key we expect the same object to be returned

    jwk1 = utils.jwk_from_pem(a_tiny_rsa_key)
    jwk2 = utils.jwk_from_pem(a_tiny_rsa_key)

    assert jwk1 is jwk2

    a_different_tiny_rsa_key = """-----BEGIN RSA PRIVATE KEY-----
MGMCAQACEQCvyNNNw4J201yzFVogcfgnAgMBAAECEE3oXe5bNlle+xU4EVHTUIEC
CQDpSvwIvDMSIQIJAMDk47DzG9FHAghtvg1TWpy3oQIJAL6NHlS+RBufAgkA6QLA
2GK4aDc=
-----END RSA PRIVATE KEY-----"""

    # But for a different key, a different object
    jwk3 = utils.jwk_from_pem(a_different_tiny_rsa_key)

    assert jwk3 is not jwk1


def test_user_code_generator():
    # Default argument, 8 characters
    user_code = utils.user_code_generator()
    assert isinstance(user_code, str)
    assert len(user_code) == 8

    for character in user_code:
        assert character >= "0"
        assert character <= "V"

    another_user_code = utils.user_code_generator()
    assert another_user_code != user_code

    shorter_user_code = utils.user_code_generator(user_code_length=1)
    assert len(shorter_user_code) == 1

    with pytest.raises(ValueError):
        utils.user_code_generator(user_code_length=0)
        utils.user_code_generator(user_code_length=-1)


def test_user_code_generator_uses_csprng(mocker):
    """
    The device-flow user code must be drawn from a cryptographically secure
    source (``secrets``), not the predictable ``random`` module, per RFC 8628
    sections 5.1/5.2.
    """
    choice = mocker.patch("oauth2_provider.utils.secrets.choice", return_value="A")

    user_code = utils.user_code_generator(user_code_length=8)

    assert user_code == "AAAAAAAA"
    assert choice.call_count == 8
    # Guard against regressing to the non-cryptographic ``random`` module.
    assert not hasattr(utils, "random")
