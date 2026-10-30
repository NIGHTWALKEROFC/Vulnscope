import pytest

from vulnscope.scope import Scope, ScopeError, blocked_reason, normalize_url


def test_normalize_url_adds_scheme():
    assert normalize_url("example.com") == "https://example.com/"


def test_normalize_url_rejects_bad_scheme():
    with pytest.raises(ValueError):
        normalize_url("ftp://example.com")


def test_blocked_reason_loopback():
    assert blocked_reason("127.0.0.1") == "loopback"
    assert blocked_reason("10.0.0.5") == "private"
    assert blocked_reason("169.254.169.254") == "cloud-metadata"
    assert blocked_reason("8.8.8.8") is None


def test_scope_host_allowed():
    scope = Scope(hosts=["example.com"], allow_subdomains=True)
    assert scope.host_allowed("example.com")
    assert scope.host_allowed("api.example.com")
    assert not scope.host_allowed("evil.com")


def test_scope_validate_ip_blocks_private_by_default():
    scope = Scope(hosts=["example.com"])
    with pytest.raises(ScopeError):
        scope.validate_ip("10.0.0.5")


def test_scope_allow_private():
    scope = Scope(hosts=["example.com"], allow_private=True)
    scope.validate_ip("10.0.0.5")
