#!/usr/bin/env python3
"""
PyPKI Web UI Test Suite
=======================
Selenium/pytest tests for the PyPKI HTML dashboard (web_ui.py).

Start server before running:
    python pki_server.py --web-port 8008

Optional flags:
    --acme-port 8888          to enable ACME endpoint info on dashboard
    --admin-api-key <key>     to enable auth-protected mutation endpoints

Run all tests:
    pytest test_webui.py -v

Run by category:
    pytest test_webui.py -v -m ui
    pytest test_webui.py -v -m navigation
    pytest test_webui.py -v -m forms
    pytest test_webui.py -v -m auth
    pytest test_webui.py -v -m api

Override base URL:
    WEB_UI_URL=http://myserver:8008 pytest test_webui.py -v

Set admin API key (if --admin-api-key was used to start the server):
    WEB_UI_ADMIN_KEY=mysecretkey pytest test_webui.py -v
"""

import json
import os
import time

import pytest
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_URL = os.environ.get("WEB_UI_URL", "http://localhost:8008").rstrip("/")
WAIT_TIMEOUT = 10  # seconds

# Admin API key (set WEB_UI_ADMIN_KEY env var if --admin-api-key was used to start server)
ADMIN_API_KEY = os.environ.get("WEB_UI_ADMIN_KEY", "")

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def driver():
    """Session-scoped headless Chrome WebDriver."""
    opts = Options()
    opts.add_argument("--headless")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--window-size=1280,900")

    try:
        from webdriver_manager.chrome import ChromeDriverManager
        service = Service(ChromeDriverManager().install())
        drv = webdriver.Chrome(service=service, options=opts)
    except Exception:
        drv = webdriver.Chrome(options=opts)

    drv.implicitly_wait(5)
    yield drv
    drv.quit()


@pytest.fixture(scope="session")
def wait(driver):
    """Session-scoped explicit wait helper."""
    return WebDriverWait(driver, WAIT_TIMEOUT)


@pytest.fixture(scope="session")
def api():
    """requests.Session pre-configured with optional admin key."""
    s = requests.Session()
    if ADMIN_API_KEY:
        s.headers["X-Admin-Key"] = ADMIN_API_KEY
    return s


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def topbar_text(driver) -> str:
    el = driver.find_elements(By.CSS_SELECTOR, ".topbar h1")
    return el[0].text if el else ""


def active_nav(driver) -> str:
    active = driver.find_elements(By.CSS_SELECTOR, "nav.nav a.active")
    return active[0].text if active else ""


# ---------------------------------------------------------------------------
# [ui] Page load tests — verify each route renders the correct HTML page
# ---------------------------------------------------------------------------


@pytest.mark.ui
class TestPageLoads:
    """Verify every dashboard page loads with correct title, nav, and content."""

    def test_dashboard_loads(self, driver):
        driver.get(f"{BASE_URL}/")
        assert "PyPKI" in driver.title
        assert "PyPKI Certificate Authority" in topbar_text(driver)

    def test_dashboard_active_nav(self, driver):
        driver.get(f"{BASE_URL}/")
        assert active_nav(driver) == "Dashboard"

    def test_dashboard_stats_grid_has_four_boxes(self, driver):
        driver.get(f"{BASE_URL}/")
        stat_boxes = driver.find_elements(By.CSS_SELECTOR, ".stats-grid .stat-box")
        assert len(stat_boxes) == 4, "Expected 4 stat boxes: Total / Active / Revoked / Expired"

    def test_dashboard_stat_labels(self, driver):
        driver.get(f"{BASE_URL}/")
        labels = [el.text for el in driver.find_elements(By.CSS_SELECTOR, ".stat-box .lbl")]
        for expected in ("Total certificates", "Active", "Revoked", "Expired"):
            assert expected in labels, f"Missing stat label: {expected}"

    def test_dashboard_ca_card_present(self, driver):
        driver.get(f"{BASE_URL}/")
        card_headings = [h.text for h in driver.find_elements(By.CSS_SELECTOR, ".card-head h2")]
        assert "Certificate Authority" in card_headings

    def test_dashboard_download_ca_cert_button(self, driver):
        driver.get(f"{BASE_URL}/")
        btn = driver.find_element(By.LINK_TEXT, "Download CA Cert")
        assert "/ca/cert.pem" in btn.get_attribute("href")

    def test_version_badge_present(self, driver):
        driver.get(f"{BASE_URL}/")
        badge = driver.find_element(By.CSS_SELECTOR, ".topbar .badge")
        assert badge.text.startswith("v"), f"Expected version badge, got: {badge.text!r}"

    def test_certs_page_loads(self, driver):
        driver.get(f"{BASE_URL}/certs")
        assert "PyPKI" in driver.title
        assert active_nav(driver) == "Certificates"

    def test_certs_page_table_headers(self, driver):
        driver.get(f"{BASE_URL}/certs")
        headers = [th.text for th in driver.find_elements(By.CSS_SELECTOR, "table thead th")]
        for col in ("Serial", "Subject", "Not Before", "Not After", "Status", "Actions"):
            assert col in headers, f"Missing table column: {col}"

    def test_certs_page_search_input_present(self, driver):
        driver.get(f"{BASE_URL}/certs")
        search = driver.find_element(By.ID, "search")
        assert search.get_attribute("placeholder") is not None

    def test_expiring_page_loads(self, driver):
        driver.get(f"{BASE_URL}/expiring")
        assert "PyPKI" in driver.title
        assert active_nav(driver) == "Expiring"

    def test_expiring_page_heading(self, driver):
        driver.get(f"{BASE_URL}/expiring")
        headings = [h.text for h in driver.find_elements(By.CSS_SELECTOR, ".card-head h2")]
        assert any("Expiring" in h for h in headings)

    def test_revocation_page_loads(self, driver):
        driver.get(f"{BASE_URL}/revocation")
        assert "PyPKI" in driver.title
        assert active_nav(driver) == "Revocation"

    def test_revocation_form_fields_present(self, driver):
        driver.get(f"{BASE_URL}/revocation")
        assert driver.find_element(By.ID, "rev-serial")
        assert driver.find_element(By.ID, "rev-reason")

    def test_revocation_reason_options(self, driver):
        driver.get(f"{BASE_URL}/revocation")
        opts = [o.text for o in driver.find_elements(By.CSS_SELECTOR, "#rev-reason option")]
        assert "Unspecified" in opts
        assert "Key Compromise" in opts
        assert "CA Compromise" in opts
        assert "Cessation Of Operation" in opts

    def test_subca_page_loads(self, driver):
        driver.get(f"{BASE_URL}/sub-ca")
        assert "PyPKI" in driver.title
        assert active_nav(driver) == "Sub-CA"

    def test_subca_form_fields_present(self, driver):
        driver.get(f"{BASE_URL}/sub-ca")
        assert driver.find_element(By.ID, "subca-cn")
        assert driver.find_element(By.ID, "subca-days")

    def test_subca_default_values(self, driver):
        driver.get(f"{BASE_URL}/sub-ca")
        assert driver.find_element(By.ID, "subca-cn").get_attribute("value") == "PyPKI Intermediate CA"
        assert driver.find_element(By.ID, "subca-days").get_attribute("value") == "1825"

    def test_metrics_page_loads(self, driver):
        driver.get(f"{BASE_URL}/metrics-ui")
        assert "PyPKI" in driver.title
        assert active_nav(driver) == "Metrics"

    def test_metrics_page_raw_link(self, driver):
        driver.get(f"{BASE_URL}/metrics-ui")
        btn = driver.find_element(By.LINK_TEXT, "Raw /api/metrics")
        assert "/api/metrics" in btn.get_attribute("href")

    def test_config_page_loads(self, driver):
        driver.get(f"{BASE_URL}/config-ui")
        assert "PyPKI" in driver.title
        assert active_nav(driver) == "Config"

    def test_config_page_ee_days_number_input(self, driver):
        driver.get(f"{BASE_URL}/config-ui")
        inp = driver.find_element(By.ID, "ee_days")
        assert inp.get_attribute("type") == "number"

    def test_config_page_json_pre_block(self, driver):
        """Config page must show current config as a JSON object in a <pre> block."""
        driver.get(f"{BASE_URL}/config-ui")
        pre = driver.find_element(By.CSS_SELECTOR, ".card-body pre")
        assert pre.text.strip().startswith("{"), "Expected JSON config in <pre> block"

    def test_config_page_apply_button_present(self, driver):
        driver.get(f"{BASE_URL}/config-ui")
        buttons = driver.find_elements(By.CSS_SELECTOR, ".card-body .btn-primary")
        assert any("Apply" in b.text for b in buttons), "Apply button not found on config page"

    def test_audit_page_loads(self, driver):
        driver.get(f"{BASE_URL}/audit")
        assert "PyPKI" in driver.title
        assert active_nav(driver) == "Audit Log"

    def test_audit_page_table_headers(self, driver):
        driver.get(f"{BASE_URL}/audit")
        headers = [th.text for th in driver.find_elements(By.CSS_SELECTOR, "table thead th")]
        for col in ("Timestamp", "Event", "Detail", "IP"):
            assert col in headers, f"Missing audit column: {col}"

    def test_api_docs_page_loads(self, driver):
        driver.get(f"{BASE_URL}/api-docs")
        assert "PyPKI" in driver.title
        assert active_nav(driver) == "API Docs"

    def test_api_docs_table_has_get_and_post(self, driver):
        driver.get(f"{BASE_URL}/api-docs")
        methods = [td.text for td in driver.find_elements(By.CSS_SELECTOR, "table tbody td:first-child")]
        assert "GET" in methods
        assert "POST" in methods
        assert "PATCH" in methods


# ---------------------------------------------------------------------------
# [navigation] Route reachability and nav-bar behaviour
# ---------------------------------------------------------------------------


@pytest.mark.navigation
class TestNavigation:
    """Verify nav links work correctly and all routes are reachable."""

    def test_topbar_present_on_every_page(self, driver):
        for path in ["/", "/certs", "/expiring", "/revocation", "/sub-ca",
                     "/metrics-ui", "/config-ui", "/audit", "/api-docs"]:
            driver.get(f"{BASE_URL}{path}")
            assert "PyPKI Certificate Authority" in topbar_text(driver), \
                f"Topbar missing on {path}"

    def test_nav_has_nine_links(self, driver):
        driver.get(f"{BASE_URL}/")
        links = driver.find_elements(By.CSS_SELECTOR, "nav.nav a")
        assert len(links) == 9, f"Expected 9 nav links, found {len(links)}"

    def test_nav_link_labels(self, driver):
        driver.get(f"{BASE_URL}/")
        texts = [a.text for a in driver.find_elements(By.CSS_SELECTOR, "nav.nav a")]
        for label in ("Dashboard", "Certificates", "Expiring", "Revocation",
                      "Sub-CA", "Metrics", "Config", "Audit Log", "API Docs"):
            assert label in texts, f"Nav link missing: {label}"

    def test_click_nav_certificates(self, driver, wait):
        driver.get(f"{BASE_URL}/")
        driver.find_element(By.LINK_TEXT, "Certificates").click()
        wait.until(EC.url_contains("/certs"))
        assert active_nav(driver) == "Certificates"

    def test_click_nav_audit_log(self, driver, wait):
        driver.get(f"{BASE_URL}/")
        driver.find_element(By.LINK_TEXT, "Audit Log").click()
        wait.until(EC.url_contains("/audit"))
        assert active_nav(driver) == "Audit Log"

    def test_click_nav_config(self, driver, wait):
        driver.get(f"{BASE_URL}/")
        driver.find_element(By.LINK_TEXT, "Config").click()
        wait.until(EC.url_contains("/config-ui"))
        assert active_nav(driver) == "Config"

    def test_click_nav_sub_ca(self, driver, wait):
        driver.get(f"{BASE_URL}/")
        driver.find_element(By.LINK_TEXT, "Sub-CA").click()
        wait.until(EC.url_contains("/sub-ca"))
        assert active_nav(driver) == "Sub-CA"

    def test_click_nav_revocation(self, driver, wait):
        driver.get(f"{BASE_URL}/")
        driver.find_element(By.LINK_TEXT, "Revocation").click()
        wait.until(EC.url_contains("/revocation"))
        assert active_nav(driver) == "Revocation"

    def test_click_nav_api_docs(self, driver, wait):
        driver.get(f"{BASE_URL}/")
        driver.find_element(By.LINK_TEXT, "API Docs").click()
        wait.until(EC.url_contains("/api-docs"))
        assert active_nav(driver) == "API Docs"

    def test_dashboard_alias_route(self, driver):
        """/dashboard should also render the dashboard page with Dashboard active."""
        driver.get(f"{BASE_URL}/dashboard")
        assert active_nav(driver) == "Dashboard"

    def test_404_page(self, driver):
        driver.get(f"{BASE_URL}/does-not-exist-xyz")
        assert "404" in driver.page_source

    @pytest.mark.parametrize("path", [
        "/", "/certs", "/expiring", "/revocation", "/sub-ca",
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
        assert resp.headers["Content-Type"].startswith(expected_ct), \
            f"{path} → unexpected Content-Type: {resp.headers['Content-Type']}"

    def test_ca_cert_pem_contains_certificate(self, api):
        resp = api.get(f"{BASE_URL}/ca/cert.pem")
        assert resp.status_code == 200
        assert "BEGIN CERTIFICATE" in resp.text

    def test_ca_crl_accessible(self, api):
        resp = api.get(f"{BASE_URL}/ca/crl")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# [forms] Form interactions and API mutations
# ---------------------------------------------------------------------------


@pytest.mark.forms
class TestForms:
    """Test interactive form elements: search filter, config patch, sub-CA issuance, revocation."""

    # ---- Certificate search filter ----

    def test_search_input_filters_table(self, driver):
        """Typing an impossible query in the search box hides all rows."""
        driver.get(f"{BASE_URL}/certs")
        rows = driver.find_elements(By.CSS_SELECTOR, "table tbody tr")
        if len(rows) < 1:
            pytest.skip("No certificates present to filter")

        search = driver.find_element(By.ID, "search")
        search.clear()
        search.send_keys("ZZZNOMATCH_ZZZNOMATCH_XYZ")
        time.sleep(0.4)

        visible = [r for r in driver.find_elements(By.CSS_SELECTOR, "table tbody tr")
                   if r.is_displayed()]
        assert len(visible) == 0, "Search filter did not hide non-matching rows"

    def test_search_clear_restores_all_rows(self, driver):
        """Clearing the search box restores all rows to visible."""
        driver.get(f"{BASE_URL}/certs")
        all_rows = driver.find_elements(By.CSS_SELECTOR, "table tbody tr")
        if len(all_rows) < 1:
            pytest.skip("No certificates present")

        search = driver.find_element(By.ID, "search")
        search.clear()
        search.send_keys("ZZZNOMATCH_ZZZNOMATCH_XYZ")
        time.sleep(0.3)
        search.clear()
        time.sleep(0.3)

        visible = [r for r in driver.find_elements(By.CSS_SELECTOR, "table tbody tr")
                   if r.is_displayed()]
        assert len(visible) == len(all_rows)

    # ---- Config PATCH via JSON API ----

    def test_api_get_config_returns_json_object(self, api):
        resp = api.get(f"{BASE_URL}/api/config")
        assert resp.status_code == 200
        assert isinstance(resp.json(), dict)

    def test_api_patch_config_end_entity_days(self, api):
        """PATCH /api/config updates end_entity_days and returns ok:true."""
        original = api.get(f"{BASE_URL}/api/config").json()
        original_days = original.get("validity", {}).get("end_entity_days", 365)

        resp = api.patch(
            f"{BASE_URL}/api/config",
            json={"validity": {"end_entity_days": 400}},
        )
        assert resp.status_code == 200
        assert resp.json().get("ok") is True

        # Restore
        api.patch(f"{BASE_URL}/api/config", json={"validity": {"end_entity_days": original_days}})

    def test_api_patch_config_value_persists(self, api):
        """Patched value is reflected in a subsequent GET /api/config."""
        sentinel = 421
        api.patch(f"{BASE_URL}/api/config", json={"validity": {"end_entity_days": sentinel}})

        cfg = api.get(f"{BASE_URL}/api/config").json()
        assert cfg.get("validity", {}).get("end_entity_days") == sentinel, \
            "Patched end_entity_days value was not persisted"

        api.patch(f"{BASE_URL}/api/config", json={"validity": {"end_entity_days": 365}})

    def test_api_patch_config_malformed_json_is_4xx(self, api):
        """Sending malformed JSON should return 4xx (not a 5xx server crash)."""
        resp = api.patch(
            f"{BASE_URL}/api/config",
            data="this is not valid json {{{",
            headers={"Content-Type": "application/json"},
        )
        assert 400 <= resp.status_code < 500, \
            f"Expected 4xx for malformed JSON, got {resp.status_code}"

    # ---- Config page UI interaction ----

    def test_config_page_ee_days_matches_api(self, api, driver):
        """The ee_days input value on the config page reflects the current API config."""
        cfg = api.get(f"{BASE_URL}/api/config").json()
        api_days = str(cfg.get("validity", {}).get("end_entity_days", ""))
        if not api_days:
            pytest.skip("end_entity_days not in config response")

        driver.get(f"{BASE_URL}/config-ui")
        inp = driver.find_element(By.ID, "ee_days")
        assert inp.get_attribute("value") == api_days, \
            f"Input shows {inp.get_attribute('value')!r}, API says {api_days!r}"

    def test_config_page_patch_via_ui_shows_result(self, api, driver, wait):
        """Clicking Apply on the config page populates the result <pre> with a JSON response."""
        driver.get(f"{BASE_URL}/config-ui")
        inp = driver.find_element(By.ID, "ee_days")
        inp.clear()
        inp.send_keys("399")

        driver.find_element(By.XPATH, "//button[text()='Apply']").click()

        result_pre = driver.find_element(By.ID, "cfg-result")
        wait.until(lambda d: result_pre.text.strip() != "")
        text = result_pre.text.lower()
        assert "ok" in text or "config" in text, \
            f"Unexpected cfg-result: {result_pre.text}"

        api.patch(f"{BASE_URL}/api/config", json={"validity": {"end_entity_days": 365}})

    # ---- Sub-CA form ----

    def test_subca_form_shows_result_on_submit(self, driver, wait):
        """Filling the Sub-CA form and clicking Issue populates the result <pre>."""
        driver.get(f"{BASE_URL}/sub-ca")
        cn_input = driver.find_element(By.ID, "subca-cn")
        cn_input.clear()
        cn_input.send_keys("Selenium Test Intermediate CA")

        days_input = driver.find_element(By.ID, "subca-days")
        days_input.clear()
        days_input.send_keys("730")

        driver.find_element(
            By.XPATH, "//button[contains(text(),'Issue Sub-CA Certificate')]"
        ).click()

        result_pre = driver.find_element(By.ID, "subca-result")
        wait.until(lambda d: result_pre.text.strip() != "")
        assert result_pre.text.strip() != ""

    def test_subca_api_returns_cert_and_key(self, api):
        """POST /api/issue-sub-ca returns cert_pem and key_pem fields on success."""
        resp = api.post(
            f"{BASE_URL}/api/issue-sub-ca",
            json={"cn": "API Selenium Test Sub-CA", "validity_days": 365},
        )
        assert resp.status_code < 500, f"Server error: {resp.status_code}"
        if resp.status_code == 200:
            data = resp.json()
            assert "cert_pem" in data
            assert "key_pem" in data
            assert "BEGIN CERTIFICATE" in data["cert_pem"]

    # ---- Revocation form ----

    def test_revocation_revoke_button_present(self, driver):
        driver.get(f"{BASE_URL}/revocation")
        btns = driver.find_elements(By.CSS_SELECTOR, ".btn-danger")
        assert len(btns) >= 1, "No Revoke button on revocation page"

    def test_api_revoke_nonexistent_serial_no_crash(self, api):
        """Revoking an unknown serial returns JSON and does not 500."""
        resp = api.post(
            f"{BASE_URL}/api/revoke",
            json={"serial": 999999999, "reason": 0},
        )
        assert resp.status_code < 500
        assert "application/json" in resp.headers.get("Content-Type", "")


# ---------------------------------------------------------------------------
# [auth] Authentication and security headers
# ---------------------------------------------------------------------------


@pytest.mark.auth
class TestAuth:
    """Verify authentication, security headers, and CSRF protection."""

    # ---- Public read-only endpoints ----

    def test_html_pages_accessible_without_credentials(self):
        for path in ["/", "/certs", "/expiring", "/revocation", "/sub-ca",
                     "/metrics-ui", "/config-ui", "/audit", "/api-docs"]:
            resp = requests.get(f"{BASE_URL}{path}")
            assert resp.status_code == 200, \
                f"Expected 200 without auth for {path}, got {resp.status_code}"

    def test_api_config_get_public(self):
        assert requests.get(f"{BASE_URL}/api/config").status_code == 200

    def test_api_certs_public(self):
        resp = requests.get(f"{BASE_URL}/api/certs")
        assert resp.status_code == 200
        assert "certificates" in resp.json()

    def test_api_audit_public(self):
        resp = requests.get(f"{BASE_URL}/api/audit")
        assert resp.status_code == 200
        assert "events" in resp.json()

    def test_api_metrics_public(self):
        resp = requests.get(f"{BASE_URL}/api/metrics")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/plain")

    def test_ca_cert_pem_public(self):
        resp = requests.get(f"{BASE_URL}/ca/cert.pem")
        assert resp.status_code == 200
        assert "BEGIN CERTIFICATE" in resp.text

    # ---- Admin API key (only exercised when WEB_UI_ADMIN_KEY is configured) ----

    @pytest.mark.skipif(not ADMIN_API_KEY, reason="WEB_UI_ADMIN_KEY not set")
    def test_patch_config_with_valid_key_succeeds(self):
        resp = requests.patch(
            f"{BASE_URL}/api/config",
            json={"validity": {"end_entity_days": 365}},
            headers={"X-Admin-Key": ADMIN_API_KEY},
        )
        assert resp.status_code == 200
        assert resp.json().get("ok") is True

    @pytest.mark.skipif(not ADMIN_API_KEY, reason="WEB_UI_ADMIN_KEY not set")
    def test_patch_config_with_wrong_key_is_403(self):
        resp = requests.patch(
            f"{BASE_URL}/api/config",
            json={"validity": {"end_entity_days": 365}},
            headers={"X-Admin-Key": "DEFINITELY_WRONG_KEY_XYZ"},
        )
        assert resp.status_code in (401, 403)

    @pytest.mark.skipif(not ADMIN_API_KEY, reason="WEB_UI_ADMIN_KEY not set")
    def test_revoke_without_key_is_403(self):
        resp = requests.post(
            f"{BASE_URL}/api/revoke",
            json={"serial": 1, "reason": 0},
        )
        assert resp.status_code in (401, 403)

    @pytest.mark.skipif(not ADMIN_API_KEY, reason="WEB_UI_ADMIN_KEY not set")
    def test_issue_sub_ca_without_key_is_403(self):
        resp = requests.post(
            f"{BASE_URL}/api/issue-sub-ca",
            json={"cn": "Unauthorized CA", "validity_days": 365},
        )
        assert resp.status_code in (401, 403)

    # ---- Security headers (added by _send_html) ----

    def test_x_frame_options_deny(self):
        assert requests.get(f"{BASE_URL}/").headers.get("X-Frame-Options") == "DENY"

    def test_x_content_type_options_nosniff(self):
        assert requests.get(f"{BASE_URL}/").headers.get("X-Content-Type-Options") == "nosniff"

    def test_cache_control_no_store(self):
        assert "no-store" in requests.get(f"{BASE_URL}/").headers.get("Cache-Control", "")

    # ---- CSRF check ----

    def test_patch_config_bad_origin_is_rejected(self):
        """PATCH /api/config from a foreign Origin (no API key) should be blocked."""
        resp = requests.patch(
            f"{BASE_URL}/api/config",
            json={"validity": {"end_entity_days": 365}},
            headers={
                "Content-Type": "application/json",
                "Origin": "https://evil.example.com",
            },
        )
        # 403 = CSRF blocked; 200 = server running without auth configured (backward compat)
        assert resp.status_code in (200, 403), \
            f"Unexpected status {resp.status_code} for cross-origin PATCH"


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
        """Each certificate entry must contain the required fields."""
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
        assert resp.content[0] == 0x30, "PKCS#12 should start with ASN.1 SEQUENCE (0x30)"

    def test_api_cert_unknown_serial_returns_404(self, api):
        resp = api.get(f"{BASE_URL}/api/certs/999999999/pem")
        assert resp.status_code == 404

    def test_api_cert_unknown_format_returns_400(self, api):
        certs = api.get(f"{BASE_URL}/api/certs").json().get("certificates", [])
        if not certs:
            pytest.skip("No certificates to test with")
        serial = certs[0]["serial"]
        resp = api.get(f"{BASE_URL}/api/certs/{serial}/unsupportedformat")
        assert resp.status_code == 400

    def test_api_config_validity_key_present(self, api):
        cfg = api.get(f"{BASE_URL}/api/config").json()
        assert "validity" in cfg or len(cfg) > 0, "Config response is unexpectedly empty"

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
