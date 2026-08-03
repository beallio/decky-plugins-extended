import audit_plugins as ap


def test_placeholder_pattern_membership_matches_named_value_group():
    for name, pattern in ap._SECRET_PATTERNS:
        assert ("value" in pattern.groupindex) == (
            name in ap._PLACEHOLDER_SECRET_PATTERNS
        ), name


def _single_finding(line: str):
    findings = ap.scan_for_secrets(line + "\n", "main.py")
    assert len(findings) == 1
    return findings[0]


def test_benign_secret_named_assignments_are_not_findings():
    lines = (
        "token = get_steam_authentication_token()",
        "api_key = _resolve_api_key_for_provider(payload)",
        "bearer = build_authorization_header_value(user)",
    )

    for line in lines:
        assert ap.scan_for_secrets(line + "\n", "main.py") == []


def test_loose_secret_patterns_require_matching_quotes():
    lines = (
        "api_key = \"aB3dE5gH7jK9mN1p'",
        "token = \"xY9zA1bC3dE5fG7hJ9kL'",
        "cf_token = \"cF3dE5gH7jK9mN1pQ3rS'",
    )

    for line in lines:
        assert ap.scan_for_secrets(line + "\n", "main.py") == []


def test_real_quoted_secret_literals_still_block():
    cases = (
        ('api_key = "aB3dE5gH7jK9mN1pQ3rS"', "SECRET_GENERIC_API_KEY"),
        (
            'apikey = "0123456789abcdef0123456789abcdef01234567"',
            "SECRET_GENERIC_API_KEY",
        ),
        ("token = 'xY9zA1bC3dE5fG7hJ9kL2mN4'", "SECRET_BEARER_TOKEN"),
        ('Bearer = "bR7dE5gH9jK1mN3pQ5rS7tV9"', "SECRET_BEARER_TOKEN"),
        ('cf_token = "cF3dE5gH7jK9mN1pQ3rS"', "SECRET_CLOUDFLARE_TOKEN"),
    )

    for line, rule_id in cases:
        findings = ap.scan_for_secrets(line + "\n", "main.py")
        expected = [finding for finding in findings if finding.rule_id == rule_id]
        assert len(expected) == 1
        assert all(finding.classification == "BLOCK" for finding in findings)


def test_literal_shape_secret_patterns_remain_blocking():
    cases = (
        ("ghp_" + "A" * 36, "SECRET_GITHUB_TOKEN"),
        ("AKIA" + "A" * 16, "SECRET_AWS_KEY"),
        ("-----BEGIN PRIVATE KEY-----", "SECRET_PRIVATE_KEY_HEADER"),
        ('password = "correct horse battery"', "SECRET_PASSWORD_LITERAL"),
    )

    for line, rule_id in cases:
        finding = _single_finding(line)
        assert finding.rule_id == rule_id
        assert finding.classification == "BLOCK"


def test_obvious_placeholders_stay_visible_as_warnings():
    cases = (
        'api_key = "your-api-key-here"',
        'token = "xxxxxxxxxxxxxxxxxxxxxxxx"',
        'api_key = "replace-with-example-value"',
        'token = "replace-with-placeholder"',
        'token = "changeme-changeme-1234"',
        'token = "your-token-value-here"',
        'token = "xxx-not-a-real-token-xxx"',
        'token = "<TODO-{{token-value}}>"',
    )

    for line in cases:
        finding = _single_finding(line)
        assert finding.classification == "PASS_WITH_WARNINGS"


def test_prose_secret_literals_stay_visible_as_warnings():
    values = (
        "Chave API Hubcap",
        "Clé API Hubcap",
        "API Key Settings",
        "Save API Key",
    )

    for value in values:
        # The patterns intentionally retain their existing 16-character minimum.
        # Pad shorter prose with whitespace so the scanner, rather than only the
        # credential-shape helper, exercises every language variant.
        finding = _single_finding(f'api_key = "{value:<16}"')
        assert finding.rule_id == "SECRET_GENERIC_API_KEY"
        assert finding.classification == "PASS_WITH_WARNINGS"


def test_any_whitespace_makes_a_matched_value_noncredential_shaped():
    finding = _single_finding('api_key = "Chave\tAPI\tHubcap"')

    assert finding.classification == "PASS_WITH_WARNINGS"
