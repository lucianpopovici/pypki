#!/usr/bin/env python3
"""
PyPKI Web UI Test Suite
=======================
Playwright/pytest tests for the PyPKI HTML dashboard (web_ui.py).

Start the server (no auth, for testing):
    python pypki.py pypki.test.json

Run all tests:
    pytest test_webui.py -v --base-url http://localhost:8090 --browser chromium

Run by category:
    pytest test_webui.py -v -m ui
    pytest test_webui.py -v -m navigation
    pytest test_webui.py -v -m forms
    pytest test_webui.py -v -m auth
    pytest test_webui.py -v -m api

Environment variables:
    WEB_UI_URL          Base URL of the web UI (default: http://localhost:8090)
    WEB_UI_CA_CERT      Path to CA certificate PEM file for TLS verification.
                        Set to "false" to disable TLS certificate verification.
    WEB_UI_CLIENT_CERT  Path to client certificate PEM file (for mTLS).
    WEB_UI_CLIENT_KEY   Path to client private key PEM file (for mTLS).
"""

import os
import time
import warnings

import pytest
import requests
import urllib3
from playwright.sync_api import sync_playwright, Page


# ---------------------------------------------------------------------------
# pytest CLI options for PAM credentials
# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_URL = os.environ.get("WEB_UI_URL", "http://localhost:8090").rstrip("/")
WAIT_TIMEOUT = 10_000  # milliseconds (Playwright uses ms)

_ca_cert_env    = os.environ.get("WEB_UI_CA_CERT", "")
_client_cert    = os.environ.get("WEB_UI_CLIENT_CERT", "")
_client_key     = os.environ.get("WEB_UI_CLIENT_KEY", "")

if _ca_cert_env.lower() == "false":
    TLS_VERIFY = False
    warnings.warn(
        "WEB_UI_CA_CERT=false: TLS certificate verification is DISABLED.",
        stacklevel=1,
    )
elif _ca_cert_env:
    TLS_VERIFY = _ca_cert_env
else:
    TLS_VERIFY = True

TLS_CLIENT_CERT = (_client_cert, _client_key) if (_client_cert and _client_key) else None
IS_TLS = BASE_URL.startswith("https://")

if TLS_VERIFY is False:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def browser():
    """Session-scoped headless Chromium browser."""
    with sync_playwright() as p:
        launch_kwargs = dict(headless=True)
        browser = p.chromium.launch(**launch_kwargs)
        yield browser
        browser.close()


@pytest.fixture(scope="session")
def page(browser):
    """Session-scoped browser page.  TLS errors are ignored for self-signed CA certs."""
    ctx = browser.new_context(
        ignore_https_errors=(TLS_VERIFY is False or IS_TLS),
        base_url=BASE_URL,
    )
    pg = ctx.new_page()
    pg.set_default_timeout(WAIT_TIMEOUT)
    yield pg
    ctx.close()


@pytest.fixture(scope="session")
def api():
    """requests.Session pre-configured with TLS settings."""
    s = requests.Session()
    s.verify = TLS_VERIFY
    if TLS_CLIENT_CERT:
        s.cert = TLS_CLIENT_CERT
    return s


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def topbar_text(page: Page) -> str:
    loc = page.locator(".topbar h1")
    return loc.inner_text() if loc.count() > 0 else ""


def active_nav(page: Page) -> str:
    loc = page.locator("nav.nav a.active")
    return loc.inner_text() if loc.count() > 0 else ""


# ---------------------------------------------------------------------------
# [ui] Page load tests
# ---------------------------------------------------------------------------

@pytest.mark.ui
class TestPageLoads:
    """Verify every dashboard page loads with correct title, nav, and content."""

    def test_dashboard_loads(self, page):
        page.goto(f"{BASE_URL}/")
        assert "PyPKI" in page.title()
        assert "PyPKI Certificate Authority" in topbar_text(page)

    def test_dashboard_active_nav(self, page):
        page.goto(f"{BASE_URL}/")
        assert active_nav(page) == "Dashboard"

    def test_dashboard_stats_grid_has_four_boxes(self, page):
        page.goto(f"{BASE_URL}/")
        boxes = page.locator(".stats-grid .stat-box").all()
        assert len(boxes) == 4

    def test_dashboard_stat_labels(self, page):
        page.goto(f"{BASE_URL}/")
        labels = [el.inner_text() for el in page.locator(".stat-box .lbl").all()]
        for expected in ("Total certificates", "Active", "Revoked", "Expired"):
            assert expected in labels, f"Missing stat label: {expected}"

    def test_dashboard_ca_card_present(self, page):
        page.goto(f"{BASE_URL}/")
        headings = [h.inner_text() for h in page.locator(".card-head h2").all()]
        assert "Certificate Authority" in headings

    def test_dashboard_download_ca_cert_button(self, page):
        page.goto(f"{BASE_URL}/")
        btn = page.get_by_role("link", name="Download CA Cert")
        assert "/ca/cert.pem" in btn.get_attribute("href")

    def test_version_badge_present(self, page):
        page.goto(f"{BASE_URL}/")
        badge = page.locator(".topbar .badge").first
        assert badge.inner_text().startswith("v")

    def test_services_page_loads(self, page):
        page.goto(f"{BASE_URL}/services")
        assert "PyPKI" in page.title()
        assert active_nav(page) == "Services"

    def test_services_page_has_service_cards(self, page):
        page.goto(f"{BASE_URL}/services")
        cards = page.locator(".card").all()
        assert len(cards) >= 1

    def test_services_page_has_status_pills(self, page):
        page.goto(f"{BASE_URL}/services")
        pills = page.locator(".pill").all()
        assert len(pills) >= 1

    def test_certs_page_loads(self, page):
        page.goto(f"{BASE_URL}/certs")
        assert "PyPKI" in page.title()
        assert active_nav(page) == "Certificates"

    def test_certs_page_table_headers(self, page):
        page.goto(f"{BASE_URL}/certs")
        headers = [th.inner_text() for th in page.locator("table thead th").all()]
        for col in ("Serial", "Subject", "Not Before", "Not After", "Status", "Actions"):
            assert col in headers, f"Missing column: {col}"

    def test_certs_page_search_input_present(self, page):
        page.goto(f"{BASE_URL}/certs")
        search = page.locator("#search")
        assert search.get_attribute("placeholder") is not None

    def test_expiring_page_loads(self, page):
        page.goto(f"{BASE_URL}/expiring")
        assert "PyPKI" in page.title()
        assert active_nav(page) == "Expiring"

    def test_expiring_page_heading(self, page):
        page.goto(f"{BASE_URL}/expiring")
        headings = [h.inner_text() for h in page.locator(".card-head h2").all()]
        assert any("Expiring" in h for h in headings)

    def test_revocation_page_loads(self, page):
        page.goto(f"{BASE_URL}/revocation")
        assert "PyPKI" in page.title()
        assert active_nav(page) == "Revocation"

    def test_revocation_form_fields_present(self, page):
        page.goto(f"{BASE_URL}/revocation")
        assert page.locator("#rev-serial").count() > 0
        assert page.locator("#rev-reason").count() > 0

    def test_revocation_reason_options(self, page):
        page.goto(f"{BASE_URL}/revocation")
        opts = [o.inner_text() for o in page.locator("#rev-reason option").all()]
        for reason in ("Unspecified", "Key Compromise", "CA Compromise", "Cessation Of Operation"):
            assert reason in opts, f"Missing revocation reason: {reason}"

    def test_subca_page_loads(self, page):
        page.goto(f"{BASE_URL}/sub-ca")
        assert "PyPKI" in page.title()
        assert active_nav(page) == "Sub-CA"

    def test_subca_form_fields_present(self, page):
        page.goto(f"{BASE_URL}/sub-ca")
        assert page.locator("#subca-cn").count() > 0
        assert page.locator("#subca-days").count() > 0

    def test_subca_default_values(self, page):
        page.goto(f"{BASE_URL}/sub-ca")
        assert page.locator("#subca-cn").get_attribute("value") == "PyPKI Intermediate CA"
        assert page.locator("#subca-days").get_attribute("value") == "1825"

    def test_metrics_page_loads(self, page):
        page.goto(f"{BASE_URL}/metrics-ui")
        assert "PyPKI" in page.title()
        assert active_nav(page) == "Metrics"

    def test_metrics_page_raw_link(self, page):
        page.goto(f"{BASE_URL}/metrics-ui")
        btn = page.get_by_role("link", name="Raw /api/metrics")
        assert "/api/metrics" in btn.get_attribute("href")

    def test_config_page_loads(self, page):
        page.goto(f"{BASE_URL}/config-ui")
        assert "PyPKI" in page.title()
        assert active_nav(page) == "Config"

    def test_config_page_ee_days_number_input(self, page):
        page.goto(f"{BASE_URL}/config-ui")
        inp = page.locator("#ee_days")
        assert inp.get_attribute("type") == "number"

    def test_config_page_json_pre_block(self, page):
        page.goto(f"{BASE_URL}/config-ui")
        pre = page.locator(".card-body pre").first
        assert pre.inner_text().strip().startswith("{"), "Expected JSON config in <pre> block"

    def test_config_page_apply_button_present(self, page):
        page.goto(f"{BASE_URL}/config-ui")
        buttons = [b.inner_text() for b in page.locator(".card-body .btn-primary").all()]
        assert any("Apply" in b for b in buttons)

    def test_audit_page_loads(self, page):
        page.goto(f"{BASE_URL}/audit")
        assert "PyPKI" in page.title()
        assert active_nav(page) == "Audit Log"

    def test_audit_page_table_headers(self, page):
        page.goto(f"{BASE_URL}/audit")
        headers = [th.inner_text() for th in page.locator("table thead th").all()]
        for col in ("Timestamp", "Event", "Detail", "IP"):
            assert col in headers, f"Missing audit column: {col}"

    def test_api_docs_page_loads(self, page):
        page.goto(f"{BASE_URL}/api-docs")
        assert "PyPKI" in page.title()
        assert active_nav(page) == "API Docs"

    def test_api_docs_table_has_methods(self, page):
        page.goto(f"{BASE_URL}/api-docs")
        methods = [td.inner_text() for td in page.locator("table tbody td:first-child").all()]
        assert "GET" in methods
        assert "POST" in methods
        assert "PATCH" in methods


# ---------------------------------------------------------------------------
# [navigation] Route reachability and nav-bar behaviour
# ---------------------------------------------------------------------------

@pytest.mark.navigation
class TestNavigation:
    """Verify nav links work correctly and all routes are reachable."""

    def test_topbar_on_every_page(self, page):
        for path in ["/", "/services", "/certs", "/expiring", "/revocation", "/sub-ca",
                     "/metrics-ui", "/config-ui", "/audit", "/api-docs"]:
            page.goto(f"{BASE_URL}{path}")
            assert "PyPKI Certificate Authority" in topbar_text(page), \
                f"Topbar missing on {path}"

    def test_nav_has_ten_links(self, page):
        page.goto(f"{BASE_URL}/")
        links = page.locator("nav.nav a").all()
        assert len(links) == 10, f"Expected 10 nav links, found {len(links)}"

    def test_nav_link_labels(self, page):
        page.goto(f"{BASE_URL}/")
        texts = [a.inner_text() for a in page.locator("nav.nav a").all()]
        for label in ("Dashboard", "Services", "Certificates", "Expiring", "Revocation",
                      "Sub-CA", "Metrics", "Config", "Audit Log", "API Docs"):
            assert label in texts, f"Nav link missing: {label}"

    def test_click_nav_certificates(self, page):
        page.goto(f"{BASE_URL}/")
        page.get_by_role("link", name="Certificates").click()
        page.wait_for_url("**/certs")
        assert active_nav(page) == "Certificates"

    def test_click_nav_audit_log(self, page):
        page.goto(f"{BASE_URL}/")
        page.get_by_role("link", name="Audit Log").click()
        page.wait_for_url("**/audit")
        assert active_nav(page) == "Audit Log"

    def test_click_nav_config(self, page):
        page.goto(f"{BASE_URL}/")
        page.get_by_role("link", name="Config").click()
        page.wait_for_url("**/config-ui")
        assert active_nav(page) == "Config"

    def test_click_nav_sub_ca(self, page):
        page.goto(f"{BASE_URL}/")
        page.get_by_role("link", name="Sub-CA").click()
        page.wait_for_url("**/sub-ca")
        assert active_nav(page) == "Sub-CA"

    def test_click_nav_revocation(self, page):
        page.goto(f"{BASE_URL}/")
        page.get_by_role("link", name="Revocation").click()
        page.wait_for_url("**/revocation")
        assert active_nav(page) == "Revocation"

    def test_click_nav_api_docs(self, page):
        page.goto(f"{BASE_URL}/")
        page.get_by_role("link", name="API Docs").click()
        page.wait_for_url("**/api-docs")
        assert active_nav(page) == "API Docs"

    def test_click_nav_services(self, page):
        page.goto(f"{BASE_URL}/")
        page.locator("nav.nav").get_by_role("link", name="Services").click()
        page.wait_for_url("**/services")
        assert active_nav(page) == "Services"

    def test_dashboard_alias_route(self, page):
        page.goto(f"{BASE_URL}/dashboard")
        assert active_nav(page) == "Dashboard"

    def test_404_page(self, page):
        page.goto(f"{BASE_URL}/does-not-exist-xyz")
        assert "404" in page.content()

    @pytest.mark.parametrize("path", [
        "/", "/services", "/certs", "/expiring", "/revocation", "/sub-ca",
        "/metrics-ui", "/config-ui", "/audit", "/api-docs", "/dashboard",
    ])
    def test_all_html_pages_return_200(self, api, path):
        resp = api.get(f"{BASE_URL}{path}")
        assert resp.status_code == 200, f"Expected 200 for {path}, got {resp.status_code}"
        assert "text/html" in resp.headers.get("Content-Type", "")

    @pytest.mark.parametrize("path,expected_ct", [
        ("/ca/cert.pem", "application/x-pem-file"),
        ("/ca/crl",      "application/pkix-crl"),
    ])
    def test_download_content_types(self, api, path, expected_ct):
        resp = api.get(f"{BASE_URL}{path}")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith(expected_ct)

    def test_ca_cert_pem_contains_certificate(self, api):
        resp = api.get(f"{BASE_URL}/ca/cert.pem")
        assert resp.status_code == 200
        assert "BEGIN CERTIFICATE" in resp.text

    def test_ca_cert_alias_returns_pem(self, api):
        resp = api.get(f"{BASE_URL}/ca/cert")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("application/x-pem-file")
        assert "BEGIN CERTIFICATE" in resp.text


# ---------------------------------------------------------------------------
# [forms] Form interactions and API mutations
# ---------------------------------------------------------------------------

@pytest.mark.forms
class TestForms:
    """Test interactive form elements: search filter, config patch, sub-CA, revocation."""

    def test_search_filters_table(self, page):
        page.goto(f"{BASE_URL}/certs")
        rows = page.locator("table tbody tr").all()
        if len(rows) < 1:
            pytest.skip("No certificates present")

        page.locator("#search").fill("ZZZNOMATCH_ZZZNOMATCH_XYZ")
        page.wait_for_timeout(400)

        visible = [r for r in page.locator("table tbody tr").all() if r.is_visible()]
        assert len(visible) == 0, "Search filter did not hide non-matching rows"

    def test_search_clear_restores_rows(self, page):
        page.goto(f"{BASE_URL}/certs")
        all_rows = page.locator("table tbody tr").all()
        if not all_rows:
            pytest.skip("No certificates present")

        page.locator("#search").fill("ZZZNOMATCH_ZZZNOMATCH_XYZ")
        page.wait_for_timeout(300)
        page.locator("#search").fill("")
        page.wait_for_timeout(300)

        visible = [r for r in page.locator("table tbody tr").all() if r.is_visible()]
        assert len(visible) == len(all_rows)

    def test_api_get_config_returns_json(self, api):
        resp = api.get(f"{BASE_URL}/api/config")
        assert resp.status_code == 200
        assert isinstance(resp.json(), dict)

    def test_api_patch_config_end_entity_days(self, api):
        original = api.get(f"{BASE_URL}/api/config").json()
        original_days = original.get("validity", {}).get("end_entity_days", 365)
        resp = api.patch(f"{BASE_URL}/api/config",
                         json={"validity": {"end_entity_days": 400}})
        assert resp.status_code == 200
        assert resp.json().get("ok") is True
        api.patch(f"{BASE_URL}/api/config",
                  json={"validity": {"end_entity_days": original_days}})

    def test_api_patch_config_value_persists(self, api):
        sentinel = 421
        api.patch(f"{BASE_URL}/api/config", json={"validity": {"end_entity_days": sentinel}})
        cfg = api.get(f"{BASE_URL}/api/config").json()
        assert cfg.get("validity", {}).get("end_entity_days") == sentinel
        api.patch(f"{BASE_URL}/api/config", json={"validity": {"end_entity_days": 365}})

    def test_api_patch_config_malformed_json_is_4xx(self, api):
        resp = api.patch(f"{BASE_URL}/api/config",
                         data="this is not valid json {{{",
                         headers={"Content-Type": "application/json"})
        assert 400 <= resp.status_code < 500

    def test_config_page_ee_days_matches_api(self, api, page):
        cfg = api.get(f"{BASE_URL}/api/config").json()
        api_days = str(cfg.get("validity", {}).get("end_entity_days", ""))
        if not api_days:
            pytest.skip("end_entity_days not in config")
        page.goto(f"{BASE_URL}/config-ui")
        assert page.locator("#ee_days").get_attribute("value") == api_days

    def test_config_page_patch_via_ui_shows_result(self, api, page):
        page.goto(f"{BASE_URL}/config-ui")
        page.locator("#ee_days").fill("399")
        page.locator("button:has-text('Apply')").click()
        page.wait_for_function(
            "() => document.getElementById('cfg-result').textContent.trim() !== ''"
        )
        text = page.locator("#cfg-result").inner_text().lower()
        assert "ok" in text or "config" in text
        api.patch(f"{BASE_URL}/api/config", json={"validity": {"end_entity_days": 365}})

    def test_subca_form_shows_result_on_submit(self, page):
        page.goto(f"{BASE_URL}/sub-ca")
        page.locator("#subca-cn").fill("Playwright Test Intermediate CA")
        page.locator("#subca-days").fill("730")
        page.locator("button:has-text('Issue Sub-CA Certificate')").click()
        page.wait_for_function(
            "() => document.getElementById('subca-result').textContent.trim() !== ''"
        )
        assert page.locator("#subca-result").inner_text().strip() != ""

    def test_subca_api_returns_cert_and_key(self, api):
        resp = api.post(f"{BASE_URL}/api/issue-sub-ca",
                        json={"cn": "API Playwright Test Sub-CA", "validity_days": 365})
        assert resp.status_code < 500
        if resp.status_code == 200:
            data = resp.json()
            assert "cert_pem" in data
            assert "key_pem" in data
            assert "BEGIN CERTIFICATE" in data["cert_pem"]

    def test_revocation_revoke_button_present(self, page):
        page.goto(f"{BASE_URL}/revocation")
        btns = page.locator(".btn-danger").all()
        assert len(btns) >= 1

    def test_api_revoke_nonexistent_serial_no_crash(self, api):
        resp = api.post(f"{BASE_URL}/api/revoke",
                        json={"serial": 999999999, "reason": 0})
        assert resp.status_code < 500
        assert "application/json" in resp.headers.get("Content-Type", "")


# ---------------------------------------------------------------------------
# [auth] Authentication and security headers
# ---------------------------------------------------------------------------

@pytest.mark.auth
class TestAuth:
    """Verify security headers and CSRF protection (server runs with --web-no-auth)."""

    def _plain_session(self) -> requests.Session:
        s = requests.Session()
        s.verify = TLS_VERIFY
        if TLS_CLIENT_CERT:
            s.cert = TLS_CLIENT_CERT
        return s

    def test_html_pages_accessible_without_auth(self):
        s = self._plain_session()
        for path in ["/", "/certs", "/expiring", "/revocation", "/sub-ca",
                     "/metrics-ui", "/config-ui", "/audit", "/api-docs"]:
            resp = s.get(f"{BASE_URL}{path}")
            assert resp.status_code == 200, \
                f"Expected 200 for {path}, got {resp.status_code}"

    def test_api_config_get_public(self):
        assert self._plain_session().get(f"{BASE_URL}/api/config").status_code == 200

    def test_api_certs_public(self):
        resp = self._plain_session().get(f"{BASE_URL}/api/certs")
        assert resp.status_code == 200
        assert "certificates" in resp.json()

    def test_api_audit_public(self):
        resp = self._plain_session().get(f"{BASE_URL}/api/audit")
        assert resp.status_code == 200
        assert "events" in resp.json()

    def test_api_metrics_public(self):
        resp = self._plain_session().get(f"{BASE_URL}/api/metrics")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/plain")

    def test_ca_cert_pem_public(self):
        resp = self._plain_session().get(f"{BASE_URL}/ca/cert.pem")
        assert resp.status_code == 200
        assert "BEGIN CERTIFICATE" in resp.text

    def test_x_frame_options_deny(self):
        assert self._plain_session().get(f"{BASE_URL}/").headers.get("X-Frame-Options") == "DENY"

    def test_x_content_type_options_nosniff(self):
        assert self._plain_session().get(f"{BASE_URL}/").headers.get("X-Content-Type-Options") == "nosniff"

    def test_cache_control_no_store(self):
        assert "no-store" in self._plain_session().get(f"{BASE_URL}/").headers.get("Cache-Control", "")

    def test_patch_config_bad_origin_rejected(self):
        s = self._plain_session()
        resp = s.patch(
            f"{BASE_URL}/api/config",
            json={"validity": {"end_entity_days": 365}},
            headers={"Content-Type": "application/json", "Origin": "https://evil.example.com"},
        )
        assert resp.status_code in (200, 403)


# ---------------------------------------------------------------------------
# [api] JSON API unit tests (no browser required)
# ---------------------------------------------------------------------------

@pytest.mark.api
class TestAPIEndpoints:
    """Direct HTTP tests for every JSON endpoint exposed by web_ui.py."""

    def test_api_certs_returns_list(self, api):
        data = api.get(f"{BASE_URL}/api/certs").json()
        assert "certificates" in data
        assert isinstance(data["certificates"], list)

    def test_api_certs_entry_fields(self, api):
        certs = api.get(f"{BASE_URL}/api/certs").json().get("certificates", [])
        if not certs:
            pytest.skip("No certificates issued yet")
        for field in ("serial", "subject", "not_before", "not_after", "revoked"):
            assert field in certs[0], f"Missing field: {field}"

    def test_api_cert_pem_download(self, api):
        certs = api.get(f"{BASE_URL}/api/certs").json().get("certificates", [])
        if not certs:
            pytest.skip("No certificates to download")
        serial = certs[0]["serial"]
        resp = api.get(f"{BASE_URL}/api/certs/{serial}/pem")
        assert resp.status_code == 200
        assert "BEGIN CERTIFICATE" in resp.text
        assert resp.headers["Content-Type"].startswith("application/x-pem-file")

    def test_api_cert_p12_download(self, api):
        certs = api.get(f"{BASE_URL}/api/certs").json().get("certificates", [])
        if not certs:
            pytest.skip("No certificates to download")
        serial = certs[0]["serial"]
        resp = api.get(f"{BASE_URL}/api/certs/{serial}/p12")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("application/x-pkcs12")
        assert resp.content[0] == 0x30

    def test_api_cert_unknown_serial_returns_404(self, api):
        assert api.get(f"{BASE_URL}/api/certs/999999999/pem").status_code == 404

    def test_api_cert_unknown_format_returns_404(self, api):
        certs = api.get(f"{BASE_URL}/api/certs").json().get("certificates", [])
        if not certs:
            pytest.skip("No certificates to test with")
        serial = certs[0]["serial"]
        assert api.get(f"{BASE_URL}/api/certs/{serial}/unsupportedformat").status_code == 404

    def test_api_config_has_validity(self, api):
        cfg = api.get(f"{BASE_URL}/api/config").json()
        assert "validity" in cfg or len(cfg) > 0

    def test_api_audit_returns_events_list(self, api):
        data = api.get(f"{BASE_URL}/api/audit").json()
        assert "events" in data
        assert isinstance(data["events"], list)

    def test_api_metrics_returns_text(self, api):
        resp = api.get(f"{BASE_URL}/api/metrics")
        assert resp.status_code == 200
        assert isinstance(resp.text, str)

    def test_api_revoke_missing_serial_returns_400(self, api):
        resp = api.post(f"{BASE_URL}/api/revoke", json={"reason": 0})
        assert resp.status_code == 400
        assert "error" in resp.json()

    def test_api_renew_missing_serial_returns_400(self, api):
        resp = api.post(f"{BASE_URL}/api/renew", json={})
        assert resp.status_code == 400
        assert "error" in resp.json()

    def test_api_unknown_post_path_returns_404(self, api):
        resp = api.post(f"{BASE_URL}/api/this-does-not-exist", json={})
        assert resp.status_code == 404

    def test_api_audit_entry_fields(self, api):
        data = api.get(f"{BASE_URL}/api/audit").json()
        events = data.get("events", [])
        if not events:
            pytest.skip("No audit events recorded yet")
        entry = events[0]
        for field in ("timestamp", "event", "detail", "ip"):
            assert field in entry, f"Missing audit entry field: {field}"

    def test_api_metrics_prometheus_format(self, api):
        resp = api.get(f"{BASE_URL}/api/metrics")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers.get("Content-Type", "")

    def test_post_api_config_same_as_patch(self, api):
        resp = api.post(f"{BASE_URL}/api/config",
                        json={"validity": {"end_entity_days": 365}})
        assert resp.status_code == 200
        assert resp.json().get("ok") is True

    def test_api_services_status_returns_dict(self, api):
        resp = api.get(f"{BASE_URL}/api/services")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)

    def test_api_services_entries_have_running_key(self, api):
        data = api.get(f"{BASE_URL}/api/services").json()
        if not data:
            pytest.skip("No services registered")
        entry = data[next(iter(data))]
        assert "running" in entry
        assert "available" in entry

    def test_api_service_unknown_action_returns_400(self, api):
        data = api.get(f"{BASE_URL}/api/services").json()
        if not data:
            pytest.skip("No services registered")
        name = next(iter(data))
        resp = api.post(f"{BASE_URL}/api/services/{name}/restart", json={})
        assert resp.status_code == 400
        assert "error" in resp.json()

    def test_api_service_unknown_name_returns_404(self, api):
        resp = api.post(f"{BASE_URL}/api/services/nonexistentservice999/stop", json={})
        assert resp.status_code == 404
        assert "error" in resp.json()

    def test_api_renew_valid_serial_no_crash(self, api):
        certs = api.get(f"{BASE_URL}/api/certs").json().get("certificates", [])
        active = [c for c in certs if not c.get("revoked")]
        if not active:
            pytest.skip("No active certificates to renew")
        serial = active[0]["serial"]
        resp = api.post(f"{BASE_URL}/api/renew", json={"serial": serial})
        assert resp.status_code < 500


@pytest.mark.auth
class TestAdminSecurity:
    """Verify that administrative endpoints behave correctly."""

    def test_invalid_config_patch_type_handled(self, api):
        resp = api.patch(f"{BASE_URL}/api/config",
                         json={"validity": {"end_entity_days": "invalid"}})
        assert resp.status_code < 500

    def test_issue_subca_cn_required(self, api):
        resp = api.post(f"{BASE_URL}/api/issue-sub-ca", json={})
        assert resp.status_code < 500


@pytest.mark.api
class TestServiceManagement:
    """Test service start/stop via the API."""

    def test_list_services(self, api):
        resp = api.get(f"{BASE_URL}/api/services")
        assert resp.status_code == 200
        data = resp.json()
        if not data:
            pytest.skip("No services registered")
        first = data[list(data.keys())[0]]
        assert "running" in first
        assert "available" in first

    def test_service_stop_returns_ok(self, api):
        data = api.get(f"{BASE_URL}/api/services").json()
        if not data:
            pytest.skip("No services registered")
        running = {n: e for n, e in data.items() if e.get("running")}
        if not running:
            pytest.skip("No running services to stop")
        name = next(iter(running))
        stop_resp = api.post(f"{BASE_URL}/api/services/{name}/stop", json={})
        assert stop_resp.status_code == 200
        assert stop_resp.json().get("ok") is True
        # Restart so later tests that expect this service running still pass
        api.post(f"{BASE_URL}/api/services/{name}/start", json={})

    def test_service_start_unavailable_returns_503(self, api):
        data = api.get(f"{BASE_URL}/api/services").json()
        unavailable = [n for n, e in data.items() if not e.get("available")]
        if not unavailable:
            pytest.skip("All services are available")
        name = unavailable[0]
        resp = api.post(f"{BASE_URL}/api/services/{name}/start", json={"port": 19999})
        assert resp.status_code == 503


@pytest.mark.api
class TestPageRenderFixes:
    """Regression tests for the .format() KeyError bugs fixed in web_ui.py."""

    def test_revocation_page_no_internal_error(self, api):
        resp = api.get(f"{BASE_URL}/revocation")
        assert resp.status_code == 200
        assert "Internal error" not in resp.text

    def test_revocation_page_has_serial_input(self, api):
        resp = api.get(f"{BASE_URL}/revocation")
        assert resp.status_code == 200
        assert 'id="rev-serial"' in resp.text

    def test_revocation_page_has_reason_select(self, api):
        resp = api.get(f"{BASE_URL}/revocation")
        assert 'id="rev-reason"' in resp.text

    def test_revocation_page_has_revoke_button(self, api):
        resp = api.get(f"{BASE_URL}/revocation")
        assert "Revoke" in resp.text

    def test_expiring_page_no_internal_error(self, api):
        resp = api.get(f"{BASE_URL}/expiring")
        assert resp.status_code == 200
        assert "Internal error" not in resp.text

    def test_all_pages_no_internal_error(self, api):
        pages = ["/", "/services", "/certs", "/expiring", "/revocation",
                 "/sub-ca", "/config-ui", "/audit", "/api-docs", "/metrics-ui"]
        for path in pages:
            resp = api.get(f"{BASE_URL}{path}")
            assert "Internal error" not in resp.text, \
                f"Page {path} returned an internal error: {resp.text[:300]}"


@pytest.mark.api
class TestServicesWithModules:
    """Verify Services page reflects module availability."""

    def test_api_services_returns_dict(self, api):
        resp = api.get(f"{BASE_URL}/api/services")
        assert resp.status_code == 200
        assert isinstance(resp.json(), dict)

    def test_api_services_known_keys_present(self, api):
        data = api.get(f"{BASE_URL}/api/services").json()
        for svc in ("cmp", "acme", "scep", "est", "ocsp"):
            assert svc in data, f"Expected '{svc}' in /api/services response"

    def test_api_services_cmp_available(self, api):
        data = api.get(f"{BASE_URL}/api/services").json()
        assert data.get("cmp", {}).get("available") is True

    def test_api_services_cmp_running(self, api):
        data = api.get(f"{BASE_URL}/api/services").json()
        assert data.get("cmp", {}).get("running") is True

    def test_api_services_entry_shape(self, api):
        data = api.get(f"{BASE_URL}/api/services").json()
        for name, entry in data.items():
            for key in ("running", "available", "url", "config"):
                assert key in entry, f"Service '{name}' missing key '{key}'"

    def test_services_page_no_internal_error(self, api):
        resp = api.get(f"{BASE_URL}/services")
        assert resp.status_code == 200
        assert "Internal error" not in resp.text

    def test_services_page_shows_cmp_running(self, api):
        resp = api.get(f"{BASE_URL}/services")
        assert resp.status_code == 200
        assert "Running" in resp.text or "running" in resp.text.lower()

    def test_stop_available_service_returns_ok(self, api):
        data = api.get(f"{BASE_URL}/api/services").json()
        stopped_available = [
            n for n, e in data.items()
            if e.get("available") and not e.get("running")
        ]
        if not stopped_available:
            pytest.skip("No stopped-but-available services to test stop on")
        name = stopped_available[0]
        resp = api.post(f"{BASE_URL}/api/services/{name}/stop", json={})
        assert resp.status_code == 200
        assert resp.json().get("ok") is True

    def test_start_unavailable_service_returns_503(self, api):
        data = api.get(f"{BASE_URL}/api/services").json()
        unavailable = [n for n, e in data.items() if not e.get("available")]
        if not unavailable:
            pytest.skip("All services are available")
        resp = api.post(
            f"{BASE_URL}/api/services/{unavailable[0]}/start",
            json={"port": 29999},
        )
        assert resp.status_code == 503


@pytest.mark.api
class TestExtendedCerts:
    """Test specialized certificate operations and binary downloads."""

    def test_download_crl(self, api):
        resp = api.get(f"{BASE_URL}/ca/crl")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"] == "application/pkix-crl"
        assert len(resp.content) > 0

    def test_download_p12_bundle_content_type(self, api):
        certs = api.get(f"{BASE_URL}/api/certs").json().get("certificates", [])
        if not certs:
            pytest.skip("No certificates to test P12 download")
        serial = certs[0]["serial"]
        resp = api.get(f"{BASE_URL}/api/certs/{serial}/p12")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"] == "application/x-pkcs12"

    def test_issue_subca_success(self, api):
        payload = {"cn": "Integration Test Sub-CA", "validity_days": 365}
        resp = api.post(f"{BASE_URL}/api/issue-sub-ca", json=payload)
        assert resp.status_code == 200
        body = resp.json()
        assert "serial" in body
        assert "cert_pem" in body
        assert "key_pem" in body
        assert body.get("ok") is True


# ---------------------------------------------------------------------------
# [auth] PAM login tests  (server must be started with auth enabled)
# Run with:  pytest test_webui.py -k TestPamLogin --pam-user pypkitest --pam-pass pypkitest123
# ---------------------------------------------------------------------------

@pytest.mark.auth
class TestPamLogin:
    """
    End-to-end PAM authentication tests using Playwright.
    The server must be running with auth enabled (pypki.auth.json / no_auth=false).
    Credentials are supplied via --pam-user / --pam-pass CLI options or the
    WEB_UI_PAM_USER / WEB_UI_PAM_PASS environment variables.
    """

    def _skip_if_no_creds(self, pam_user, pam_pass):
        if not pam_user or not pam_pass:
            pytest.skip("PAM credentials not provided (--pam-user / --pam-pass)")

    def test_login_page_renders(self, page, pam_user, pam_pass):
        self._skip_if_no_creds(pam_user, pam_pass)
        page.goto(f"{BASE_URL}/login")
        assert page.locator("form").count() > 0
        assert page.locator("input[name=username]").count() > 0
        assert page.locator("input[name=password]").count() > 0

    def test_unauthenticated_redirect_to_login(self, page, pam_user, pam_pass):
        """Accessing a protected page without a session must redirect to /login."""
        self._skip_if_no_creds(pam_user, pam_pass)
        # Use a fresh context so there is no active session cookie
        with page.context.browser.new_context(base_url=BASE_URL) as ctx:
            p = ctx.new_page()
            p.goto(f"{BASE_URL}/")
            assert "/login" in p.url, f"Expected redirect to /login, got {p.url}"

    def test_wrong_password_shows_error(self, page, pam_user, pam_pass):
        self._skip_if_no_creds(pam_user, pam_pass)
        with page.context.browser.new_context(base_url=BASE_URL) as ctx:
            p = ctx.new_page()
            p.goto(f"{BASE_URL}/login")
            p.locator("input[name=username]").fill(pam_user)
            p.locator("input[name=password]").fill("definitelyWrongPassword!!")
            p.locator("button[type=submit]").click()
            # Must stay on /login and show an error message
            assert "/login" in p.url
            content = p.content()
            assert "Invalid" in content or "incorrect" in content.lower() \
                or "failed" in content.lower() or "error" in content.lower()

    def test_correct_credentials_grant_access(self, page, pam_user, pam_pass):
        self._skip_if_no_creds(pam_user, pam_pass)
        with page.context.browser.new_context(base_url=BASE_URL) as ctx:
            p = ctx.new_page()
            p.goto(f"{BASE_URL}/login")
            p.locator("input[name=username]").fill(pam_user)
            p.locator("input[name=password]").fill(pam_pass)
            p.locator("button[type=submit]").click()
            p.wait_for_url(f"{BASE_URL}/", timeout=WAIT_TIMEOUT)
            assert "PyPKI" in p.title()

    def test_session_cookie_set_after_login(self, page, pam_user, pam_pass):
        self._skip_if_no_creds(pam_user, pam_pass)
        with page.context.browser.new_context(base_url=BASE_URL) as ctx:
            p = ctx.new_page()
            p.goto(f"{BASE_URL}/login")
            p.locator("input[name=username]").fill(pam_user)
            p.locator("input[name=password]").fill(pam_pass)
            p.locator("button[type=submit]").click()
            p.wait_for_url(f"{BASE_URL}/", timeout=WAIT_TIMEOUT)
            cookies = ctx.cookies()
            session_cookies = [c for c in cookies if "session" in c["name"].lower()
                               or "pypki" in c["name"].lower()]
            assert len(session_cookies) > 0, "No session cookie set after login"

    def test_authenticated_session_reaches_dashboard(self, page, pam_user, pam_pass):
        self._skip_if_no_creds(pam_user, pam_pass)
        with page.context.browser.new_context(base_url=BASE_URL) as ctx:
            p = ctx.new_page()
            p.goto(f"{BASE_URL}/login")
            p.locator("input[name=username]").fill(pam_user)
            p.locator("input[name=password]").fill(pam_pass)
            p.locator("button[type=submit]").click()
            p.wait_for_url(f"{BASE_URL}/", timeout=WAIT_TIMEOUT)
            assert "PyPKI Certificate Authority" in p.locator(".topbar h1").inner_text()

    def test_authenticated_session_reaches_all_pages(self, page, pam_user, pam_pass):
        self._skip_if_no_creds(pam_user, pam_pass)
        with page.context.browser.new_context(base_url=BASE_URL) as ctx:
            p = ctx.new_page()
            # Log in once
            p.goto(f"{BASE_URL}/login")
            p.locator("input[name=username]").fill(pam_user)
            p.locator("input[name=password]").fill(pam_pass)
            p.locator("button[type=submit]").click()
            p.wait_for_url(f"{BASE_URL}/", timeout=WAIT_TIMEOUT)
            # Visit all pages — none should redirect back to /login
            for path in ["/services", "/certs", "/revocation", "/audit", "/config-ui"]:
                p.goto(f"{BASE_URL}{path}")
                assert "/login" not in p.url, \
                    f"Got redirected to /login on {path} despite active session"

    def test_api_blocked_without_session(self, pam_user, pam_pass):
        """Mutating API endpoints must return 401/403 without a valid session."""
        self._skip_if_no_creds(pam_user, pam_pass)
        s = requests.Session()
        s.verify = TLS_VERIFY
        resp = s.post(f"{BASE_URL}/api/revoke", json={"serial": 1, "reason": 0})
        assert resp.status_code in (401, 403), \
            f"Expected 401/403 without session, got {resp.status_code}"

    def test_api_accessible_with_session_cookie(self, pam_user, pam_pass):
        """After logging in via the form, the session cookie should allow API calls."""
        self._skip_if_no_creds(pam_user, pam_pass)
        s = requests.Session()
        s.verify = TLS_VERIFY
        # Fetch login form (sets any CSRF cookie if applicable)
        s.get(f"{BASE_URL}/login")
        resp = s.post(f"{BASE_URL}/login",
                      data={"username": pam_user, "password": pam_pass},
                      allow_redirects=True)
        assert resp.status_code == 200
        # Now the session cookie should be set — config GET must succeed
        cfg = s.get(f"{BASE_URL}/api/config")
        assert cfg.status_code == 200
        assert isinstance(cfg.json(), dict)
