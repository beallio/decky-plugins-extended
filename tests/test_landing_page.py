import re
from html.parser import HTMLParser
from pathlib import Path

STATIC = Path(__file__).parents[1] / "static"
LANDING_PAGE = STATIC / "index.html"
STOREFRONT_CSS = STATIC / "storefront.css"
STOREFRONT_JS = STATIC / "storefront.js"


class StorefrontParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements = []
        self.ids = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        self.elements.append((tag, attributes))
        if "id" in attributes:
            self.ids.append(attributes["id"])


def _html() -> str:
    return LANDING_PAGE.read_text(encoding="utf-8")


def _parser() -> StorefrontParser:
    parser = StorefrontParser()
    parser.feed(_html())
    return parser


def _has_element(parser, tag, **attributes) -> bool:
    return any(
        element_tag == tag
        and all(
            element_attributes.get(key) == value for key, value in attributes.items()
        )
        for element_tag, element_attributes in parser.elements
    )


def test_storefront_has_unique_ids_and_referenced_local_assets():
    parser = _parser()

    assert len(parser.ids) == len(set(parser.ids))
    assert _has_element(parser, "link", rel="stylesheet", href="storefront.css")
    assert _has_element(parser, "script", type="module", src="storefront.js")
    assert STOREFRONT_CSS.is_file()
    assert STOREFRONT_JS.is_file()


def test_storefront_keeps_visible_stable_and_testing_fallback_urls():
    html = _html()

    assert "https://decky-extended-plugins.beallio.com/plugins.json" in html
    assert "https://decky-extended-plugins.beallio.com/testing_plugins.json" in html
    assert 'data-fallback-channel="stable"' in html
    assert 'data-fallback-channel="testing"' in html


def test_storefront_semantics_controls_and_accessible_dialogs():
    parser = _parser()

    assert _has_element(parser, "nav", **{"aria-label": "Primary navigation"})
    assert _has_element(parser, "section", **{"aria-label": "Store status"})
    assert _has_element(parser, "input", id="search", type="search")
    assert _has_element(parser, "select", id="sort")
    assert _has_element(parser, "div", id="plugin-grid")
    assert _has_element(parser, "p", id="copy-status", role="status")
    assert _has_element(parser, "p", id="setup-copy-status", role="status")
    assert _has_element(parser, "div", id="catalog-error", role="alert")
    assert _has_element(parser, "section", id="setup-dialog", role="dialog")
    assert _has_element(parser, "section", id="detail-dialog", role="dialog")

    dialog_elements = [
        attributes
        for tag, attributes in parser.elements
        if tag == "section" and attributes.get("role") == "dialog"
    ]
    assert len(dialog_elements) == 2
    assert all(dialog.get("aria-modal") == "true" for dialog in dialog_elements)
    assert all(dialog.get("aria-labelledby") for dialog in dialog_elements)


def test_storefront_has_no_inline_event_handlers():
    parser = _parser()

    assert not [
        attribute
        for _, attributes in parser.elements
        for attribute in attributes
        if attribute.lower().startswith("on")
    ]


def test_storefront_styles_cover_responsive_focus_and_reduced_motion_states():
    css = STOREFRONT_CSS.read_text(encoding="utf-8")

    assert ":focus-visible" in css
    assert "prefers-reduced-motion: reduce" in css
    assert "grid-template-columns: repeat(3, minmax(0, 1fr))" in css
    assert "grid-template-columns: repeat(2, minmax(0, 1fr))" in css
    assert "grid-template-columns: 1fr" in css
    assert ".status-value" in css
    assert ".status-content" in css
    assert ".plugin-card:focus-within" in css
    assert "justify-content: center" in css
    assert "text-align: center" in css
    assert "@media (max-width: 920px)" in css
    assert "@media (max-width: 640px)" in css


def test_catalog_introduction_and_removed_badge_copy_are_exact():
    html = _html()
    introduction = re.search(
        r'<p id="catalog-introduction">(?P<text>.*?)</p>', html, flags=re.DOTALL
    )

    assert introduction
    assert " ".join(introduction.group("text").split()) == (
        "Search by name, author, or purpose."
    )
    assert "High-signal badges" not in html
    assert "High-signal badges" not in STOREFRONT_JS.read_text(encoding="utf-8")
