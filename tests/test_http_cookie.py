"""Transport encoding must preserve semicolons inside opaque cookie values."""
from http.cookies import SimpleCookie

import pytest

from cryptoscan.http_cookie import cookie_request_header, local_cookie_parse_check


@pytest.mark.parametrize("value", [
    "abcdef;012345",
    "ciphertext_hex;tag_hex",
    "a,b;c=d",
    "simple",
])
def test_cookie_header_roundtrip(value):
    header = cookie_request_header("auth", value)
    assert header.startswith("Cookie: auth=")
    jar = SimpleCookie()
    jar.load(header.removeprefix("Cookie: "))
    assert jar["auth"].value == value
    assert local_cookie_parse_check("auth", value)


def test_raw_semicolon_is_unsafe_but_encoded_is_safe():
    token = "deadbeef;00112233"
    jar = SimpleCookie()
    jar.load("auth=" + token)
    assert "auth" not in jar or jar["auth"].value != token
    assert local_cookie_parse_check("auth", token)


def test_cookie_header_validation():
    with pytest.raises(ValueError):
        cookie_request_header("foo;bar", "ok")
    with pytest.raises(ValueError):
        cookie_request_header("auth", "bad\r\nInjected: yes")
