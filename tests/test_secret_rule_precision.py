import hashlib

import audit_plugins as ap


def test_placeholder_pattern_membership_matches_named_value_group():
    for name, pattern in ap._SECRET_PATTERNS:
        assert ("value" in pattern.groupindex) == (
            name in ap._PLACEHOLDER_SECRET_PATTERNS
        ), name


def _single_finding(line: str, path: str = "main.py"):
    findings = ap.scan_for_secrets(line + "\n", path)
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


def test_placeholder_requires_explicit_fixture_path_for_warning():
    line = 'api_key = "your_provider_token"'

    assert _single_finding(line).classification == "BLOCK"
    finding = _single_finding(line, "tests/fixtures/config.py")

    assert finding.classification == "PASS_WITH_WARNINGS"
    assert "your_provider_token" not in finding.evidence


def test_example_filename_is_an_explicit_fixture_path():
    finding = _single_finding(
        'token = "{{provider_authentication_token}}"', "config.example.py"
    )

    assert finding.classification == "PASS_WITH_WARNINGS"


def test_fixture_path_requires_an_exact_segment():
    finding = _single_finding('api_key = "your_provider_token"', "contest/config.py")

    assert finding.classification == "BLOCK"


def test_provider_shaped_repeated_placeholder_warns_only_in_fixture():
    value = "ghp_" + "X" * 36

    assert _single_finding(value).classification == "BLOCK"
    assert _single_finding(value, "mocks/github.py").classification == (
        "PASS_WITH_WARNINGS"
    )


def test_inline_test_comment_does_not_downgrade_real_token():
    finding = _single_finding('api_key = "aB3dE5gH7jK9mN1pQ3rS"  # test', "main.py")

    assert finding.classification == "BLOCK"


def test_prose_secret_literals_remain_critical():
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
        assert finding.classification == "BLOCK"


def test_whitespace_does_not_downgrade_a_matched_value():
    finding = _single_finding('api_key = "Chave\tAPI\tHubcap"')

    assert finding.classification == "BLOCK"


def test_secret_evidence_reports_shape_without_leaking_value():
    value = "aB3dE5gH7jK9mN1pQ3rS"
    finding = _single_finding(f'api_key = "{value}"')

    assert f"value_length={len(value)}" in finding.evidence
    assert "contains_whitespace=no" in finding.evidence
    assert "entirely_alphabetic=no" in finding.evidence

    forbidden = {value, hashlib.sha256(value.encode()).hexdigest()}
    forbidden.update(value[index : index + 4] for index in range(len(value) - 3))
    assert all(fragment not in finding.evidence for fragment in forbidden)

    prose = _single_finding('api_key = "Chave API Hubcap"')
    assert "value_length=16" in prose.evidence
    assert "contains_whitespace=yes" in prose.evidence
    assert "entirely_alphabetic=yes" in prose.evidence
