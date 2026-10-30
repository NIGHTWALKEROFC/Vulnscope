from vulnscope.cvss import cvss3_score, severity_from_score


def test_cvss3_known_vector():
    score = cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score == 9.8


def test_severity_bounds():
    assert severity_from_score(9.8) == "critical"
    assert severity_from_score(7.0) == "high"
    assert severity_from_score(4.0) == "medium"
    assert severity_from_score(0.1) == "low"
    assert severity_from_score(None) == "unknown"
