from vulnscope.versions import compare_versions, extract_version, in_range


def test_compare_basic():
    assert compare_versions("1.2.3", "1.2.4") < 0
    assert compare_versions("1.10.0", "1.9.0") > 0
    assert compare_versions("1.0.0", "1.0.0") == 0


def test_compare_prerelease():
    assert compare_versions("1.0.0-beta", "1.0.0") < 0
    assert compare_versions("1.0.0-alpha", "1.0.0-beta") < 0


def test_in_range():
    assert in_range("1.5.0", start_incl="1.0.0", end_excl="2.0.0")
    assert not in_range("2.0.0", start_incl="1.0.0", end_excl="2.0.0")
    assert in_range("1.0.0", start_incl="1.0.0", end_incl="1.0.0")


def test_extract_version():
    assert extract_version("Apache/2.4.41 (Ubuntu)") == "2.4.41"
    assert extract_version("nginx") is None
