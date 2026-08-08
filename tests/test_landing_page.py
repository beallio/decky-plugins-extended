import re
from pathlib import Path

LANDING_PAGE = Path(__file__).parents[1] / "static" / "index.html"


def _landing_page() -> str:
    return LANDING_PAGE.read_text(encoding="utf-8")


def test_audit_and_github_links_use_compact_top_right_utility_group():
    html = _landing_page()
    utility_css = re.search(r"\.utility-links\s*\{(?P<declarations>[^}]*)\}", html)

    assert utility_css
    declarations = utility_css.group("declarations")
    assert "position: absolute" in declarations
    assert "top:" in declarations
    assert "right:" in declarations
    assert '<div class="utility-links" aria-label="Site links">' in html
    assert (
        '<a href="audit.html" class="utility-link audit" aria-label="View audit log"'
    ) in html
    assert (
        '<a href="https://github.com/beallio/decky-plugins-extended" '
        'class="utility-link github"'
    ) in html


def test_utility_links_have_distinct_accessible_icons():
    html = _landing_page()

    assert '<svg class="utility-icon audit-icon"' in html
    assert '<svg class="utility-icon github-icon"' in html
    assert 'aria-label="View source on GitHub"' in html
    assert 'aria-label="View audit log"' in html


def test_audit_url_is_not_repeated_in_visible_catalog_urls():
    html = _landing_page()
    visible_urls = html.split('<div class="urls">', 1)[1].split("</div>", 1)[0]

    assert "plugins.json" in visible_urls
    assert "testing_plugins.json" in visible_urls
    assert "audit.html" not in visible_urls
