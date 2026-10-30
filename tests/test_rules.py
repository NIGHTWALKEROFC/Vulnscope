from vulnscope.rules import jslibs, secrets


def test_jslib_detect_from_name():
    out = jslibs.detect_from_name("/static/js/jquery-1.12.4.min.js")
    assert ("jquery", "1.12.4") in out


def test_jslib_detect_from_content():
    out = jslibs.detect_from_content("/*! jQuery v3.3.1 | (c) JS Foundation */")
    assert ("jquery", "3.3.1") in out


def test_secret_detection_masks_value():
    hits = secrets.scan_text('aws_key = "AKIAABCDEFGHIJKLMNOP"')
    assert hits
    assert hits[0]["masked"] != "AKIAABCDEFGHIJKLMNOP"
    assert "AKIA" in hits[0]["masked"]


def test_secret_placeholder_skipped():
    hits = secrets.scan_text('password = "changeme"')
    assert not any(h["rule_id"] == "generic-secret" for h in hits)
