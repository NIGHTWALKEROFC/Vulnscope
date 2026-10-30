from vulnscope.redact import mask, redact_text


def test_mask_short():
    assert mask("abc") == "***"


def test_mask_long():
    out = mask("supersecretvalue123")
    assert out.startswith("supe")
    assert "secret" not in out


def test_redact_authorization_header():
    text = "Authorization: Bearer abcdefghijklmnop"
    assert "abcdefghijklmnop" not in redact_text(text)


def test_redact_aws_key():
    text = "key=AKIAABCDEFGHIJKLMNOP"
    assert "AKIAABCDEFGHIJKLMNOP" not in redact_text(text)
