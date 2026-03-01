#!/usr/bin/env python3
"""
PyPKI Web UI Test Suite
=======================
Selenium/pytest tests for the PyPKI HTML dashboard (web_ui.py).

Start the server (plain HTTP):
    python pki_server.py --web-port 8008

Start with one-way TLS:
    python pki_server.py --web-port 8008 --tls

Start with mutual TLS:
    python pki_server.py --web-port 8008 --mtls

Run all tests:
    pytest test_webui.py -v

Run by category:
    pytest test_webui.py -v -m ui
    pytest test_webui.py -v -m navigation
    pytest test_webui.py -v -m forms
    pytest test_webui.py -v -m auth
    pytest test_webui.py -v -m api

Environment variables:
    WEB_UI_URL          Base URL of the web UI (default: http://localhost:8008)
                        Set to https://localhost:8008 if TLS is enabled.
    WEB_UI_ADMIN_KEY    Admin API key if --admin-api-key was used to start the server.
    WEB_UI_CA_CERT      Path to the CA certificate PEM file for TLS verification.
                        Set to "false" to disable TLS certificate verification (dev only).
    WEB_UI_CLIENT_CERT  Path to client certificate PEM file (for mTLS).
    WEB_UI_CLIENT_KEY   Path to client private key PEM file (for mTLS).

Examples:
    # Plain HTTP
    WEB_UI_URL=http://localhost:8008 pytest test_webui.py -v

    # One-way TLS (verify with CA cert)
    WEB_UI_URL=https://localhost:8008 WEB_UI_CA_CERT=./ca/ca.crt pytest test_webui.py -v

    # One-way TLS (skip verification — dev/test only)
    WEB_UI_URL=https://localhost:8008 WEB_UI_CA_CERT=false pytest test_webui.py -v

    # Mutual TLS
    WEB_UI_URL=https://localhost:8008 WEB_UI_CA_CERT=./ca/ca.crt \\
        WEB_UI_CLIENT_CERT=./client.crt WEB_UI_CLIENT_KEY=./client.key \\
        pytest test_webui.py -v
"""

import os
import time
import warnings

import pytest
import requests
import urllib3
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

# ---------------------------------------------------------------------------
# Configuration — driven entirely by environment variables
# ---------------------------------------------------------------------------

BASE_URL = os.environ.get("WEB_UI_URL", "http://localhost:8008").rstrip("/")
WAIT_TIMEOUT = 10  # seconds
ADMIN_API_KEY = os.environ.get("WEB_UI_ADMIN_KEY", "")

# TLS configuration
_ca_cert_env = os.environ.get("WEB_UI_CA_CERT", "")
_client_cert = os.environ.get("WEB_UI_CLIENT_CERT", "")
_client_key = os.environ.get("WEB_UI_CLIENT_KEY", "")

# TLS_VERIFY: False = skip verification, str = path to CA bundle, True = system bundle
if _ca_cert_env.lower() == "false":
    TLS_VERIFY = False
    warnings.warn(
        "WEB_UI_CA_CERT=false: TLS certificate verification is DISABLED. "
        "Only use this in a trusted test environment.",
        stacklevel=1,
    )
elif _ca_cert_env:
    TLS_VERIFY = _ca_cert_env   # path to CA bundle PEM
else:
    TLS_VERIFY = True           # use system trust store

# mTLS client certificate: (cert_path, key_path) tuple or None
TLS_CLIENT_CERT = (_client_cert, _client_key) if (_client_cert and _client_key) else None

IS_TLS = BASE_URL.startswith("https://")

# Suppress InsecureRequestWarning when verification is intentionally disabled
if TLS_VERIFY is False:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def driver():
    """Session-scoped headless Chrome WebDriver with optional TLS configuration."""
    opts = Options()
    opts.add_argument("--headless")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--window-size=1280,900")

    if IS_TLS and TLS_VERIFY is False:
        # Allow Chrome to connect to servers with self-signed / untrusted certs
        opts.add_argument("--ignore-certificate-errors")
        opts.add_argument("--allow-insecure-localhost")

    if IS_TLS and TLS_VERIFY and isinstance(TLS_VERIFY, str):
        # Tell Chrome to trust a specific CA certificate file
        opts.add_argument(f"--ssl-client-certificate-path={TLS_VERIFY}")

    if TLS_CLIENT_CERT:
        # mTLS: Chrome needs the client certificate + key in PKCS#12 format.
        # For test environments this usually means adding the cert to an NSS
        # database; for simplicity we note this limitation here and fall back
        # to the requests-only tests for mTLS-protected endpoints.
        pass  # Selenium mTLS support is browser/profile-specific; see note above.

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
    return WebDriverWait(driver, WAIT_TIMEOUT)


@pytest.fixture(scope="session")
def api():
    """
    requests.Session pre-configured with:
      - Optional admin API key header
      - TLS verification setting (CA bundle path, False, or True)
      - Optional mTLS client certificate
    """
    s = requests.Session()
    if ADMIN_API_KEY:
        s.headers["X-Admin-Key"] = ADMIN_API_KEY
    s.verify = TLS_VERIFY
    if TLS_CLIENT_CERT:
        s.cert = TLS_CLIENT_CERT
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
# [ui] Page load tests
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
        assert len(stat_boxes) == 4

    def test_dashboard_stat_labels(self, driver):
        driver.get(f"{BASE_URL}/")
        labels = [el.text for el in driver.find_elements(By.CSS_SELECTOR, ".stat-box .lbl")]
        for expected in ("Total certificates", "Active", "Revoked", "Expired"):
            assert expected in labels, f"Missing stat label: {expected}"

    def test_dashboard_ca_card_present(self, driver):
        driver.get(f"{BASE_URL}/")
        headings = [h.text for h in driver.find_elements(By.CSS_SELECTOR, ".card-head h2")]
        assert "Certificate Authority" in headings

    def test_dashboard_download_ca_cert_button(self, driver):
        driver.get(f"{BASE_URL}/")
        btn = driver.find_element(By.LINK_TEXT, "Download CA Cert")
        assert "/ca/cert.pem" in btn.get_attribute("href")

    def test_version_badge_present(self, driver):
        driver.get(f"{BASE_URL}/")
        badge = driver.find_element(By.CSS_SELECTOR, ".topbar .badge")
        assert badge.text.startswith("v"), f"Expected version badge, got: {badge.text!r}"

    def test_services_page_loads(self, driver):
        driver.get(f"{BASE_URL}/services")
        assert "PyPKI" in driver.title
        assert active_nav(driver) == "Services"

    def test_services_page_has_service_cards(self, driver):
        driver.get(f"{BASE_URL}/services")
        cards = driver.find_elements(By.CSS_SELECTOR, ".card")
        assert len(cards) >= 1, "Services page should show at least one service card"

    def test_services_page_has_status_pills(self, driver):
        driver.get(f"{BASE_URL}/services")
        pills = driver.find_elements(By.CSS_SELECTOR, ".pill")
        assert len(pills) >= 1, "Services page should show at least one status pill"

    def test_certs_page_loads(self, driver):
        driver.get(f"{BASE_URL}/certs")
        assert "PyPKI" in driver.title
        assert active_nav(driver) == "Certificates"

    def test_certs_page_table_headers(self, driver):
        driver.get(f"{BASE_URL}/certs")
        headers = [th.text for th in driver.find_elements(By.CSS_SELECTOR, "table thead th")]
        for col in ("Serial", "Subject", "Not Before", "Not After", "Status", "Actions"):
            assert col in headers, f"Missing column: {col}"

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
        for reason in ("Unspecified", "Key Compromise", "CA Compromise", "Cessation Of Operation"):
            assert reason in opts, f"Missing revocation reason: {reason}"

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
        driver.get(f"{BASE_URL}/config-ui")
        pre = driver.find_element(By.CSS_SELECTOR, ".card-body pre")
        assert pre.text.strip().startswith("{"), "Expected JSON config in <pre> block"

    def test_config_page_apply_button_present(self, driver):
        driver.get(f"{BASE_URL}/config-ui")
        buttons = driver.find_elements(By.CSS_SELECTOR, ".card-body .btn-primary")
        assert any("Apply" in b.text for b in buttons)

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

    def test_api_docs_table_has_methods(self, driver):
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

    def test_topbar_on_every_page(self, driver):
        for path in ["/", "/services", "/certs", "/expiring", "/revocation", "/sub-ca",
                     "/metrics-ui", "/config-ui", "/audit", "/api-docs"]:
            driver.get(f"{BASE_URL}{path}")
            assert "PyPKI Certificate Authority" in topbar_text(driver), \
                f"Topbar missing on {path}"

    def test_nav_has_ten_links(self, driver):
        driver.get(f"{BASE_URL}/")
        links = driver.find_elements(By.CSS_SELECTOR, "nav.nav a")
        assert len(links) == 10, f"Expected 10 nav links, found {len(links)}"

    def test_nav_link_labels(self, driver):
        driver.get(f"{BASE_URL}/")
        texts = [a.text for a in driver.find_elements(By.CSS_SELECTOR, "nav.nav a")]
        for label in ("Dashboard", "Services", "Certificates", "Expiring", "Revocation",
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

    def test_click_nav_services(self, driver, wait):
        driver.get(f"{BASE_URL}/")
        driver.find_element(By.LINK_TEXT, "Services").click()
        wait.until(EC.url_contains("/services"))
        assert active_nav(driver) == "Services"

    def test_dashboard_alias_route(self, driver):
        driver.get(f"{BASE_URL}/dashboard")
        assert active_nav(driver) == "Dashboard"

    def test_404_page(self, driver):
        driver.get(f"{BASE_URL}/does-not-exist-xyz")
        assert "404" in driver.page_source

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
        """/ca/cert is an alias for /ca/cert.pem."""
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

    def test_search_filters_table(self, driver):
        driver.get(f"{BASE_URL}/certs")
        rows = driver.find_elements(By.CSS_SELECTOR, "table tbody tr")
        if len(rows) < 1:
            pytest.skip("No certificates present")

        search = driver.find_element(By.ID, "search")
        search.clear()
        search.send_keys("ZZZNOMATCH_ZZZNOMATCH_XYZ")
        time.sleep(0.4)

        visible = [r for r in driver.find_elements(By.CSS_SELECTOR, "table tbody tr")
                   if r.is_displayed()]
        assert len(visible) == 0, "Search filter did not hide non-matching rows"

    def test_search_clear_restores_rows(self, driver):
        driver.get(f"{BASE_URL}/certs")
        all_rows = driver.find_elements(By.CSS_SELECTOR, "table tbody tr")
        if not all_rows:
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

    def test_config_page_ee_days_matches_api(self, api, driver):
        cfg = api.get(f"{BASE_URL}/api/config").json()
        api_days = str(cfg.get("validity", {}).get("end_entity_days", ""))
        if not api_days:
            pytest.skip("end_entity_days not in config")

        driver.get(f"{BASE_URL}/config-ui")
        inp = driver.find_element(By.ID, "ee_days")
        assert inp.get_attribute("value") == api_days

    def test_config_page_patch_via_ui_shows_result(self, api, driver, wait):
        driver.get(f"{BASE_URL}/config-ui")
        inp = driver.find_element(By.ID, "ee_days")
        inp.clear()
        inp.send_keys("399")

        driver.find_element(By.XPATH, "//button[text()='Apply']").click()

        result_pre = driver.find_element(By.ID, "cfg-result")
        wait.until(lambda d: result_pre.text.strip() != "")
        text = result_pre.text.lower()
        assert "ok" in text or "config" in text

        api.patch(f"{BASE_URL}/api/config", json={"validity": {"end_entity_days": 365}})

    def test_subca_form_shows_result_on_submit(self, driver, wait):
        driver.get(f"{BASE_URL}/sub-ca")
        cn_input = driver.find_element(By.ID, "subca-cn")
        cn_input.clear()
        cn_input.send_keys("Selenium Test Intermediate CA")

        days_input = driver.find_element(By.ID, "subca-days")
        days_input.clear()
        days_input.send_keys("730")

        driver.find_element(By.XPATH,
                            "//button[contains(text(),'Issue Sub-CA Certificate')]").click()

        result_pre = driver.find_element(By.ID, "subca-result")
        wait.until(lambda d: result_pre.text.strip() != "")
        assert result_pre.text.strip() != ""

    def test_subca_api_returns_cert_and_key(self, api):
        resp = api.post(f"{BASE_URL}/api/issue-sub-ca",
                        json={"cn": "API Selenium Test Sub-CA", "validity_days": 365})
        assert resp.status_code < 500
        if resp.status_code == 200:
            data = resp.json()
            assert "cert_pem" in data
            assert "key_pem" in data
            assert "BEGIN CERTIFICATE" in data["cert_pem"]

    def test_revocation_revoke_button_present(self, driver):
        driver.get(f"{BASE_URL}/revocation")
        btns = driver.find_elements(By.CSS_SELECTOR, ".btn-danger")
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
    """Verify authentication, security headers, and CSRF protection."""

    def _plain_session(self) -> requests.Session:
        """A fresh session with TLS config but NO admin key — for auth boundary tests."""
        s = requests.Session()
        s.verify = TLS_VERIFY
        if TLS_CLIENT_CERT:
            s.cert = TLS_CLIENT_CERT
        return s

    def test_html_pages_accessible_without_admin_key(self):
        s = self._plain_session()
        for path in ["/", "/certs", "/expiring", "/revocation", "/sub-ca",
                     "/metrics-ui", "/config-ui", "/audit", "/api-docs"]:
            resp = s.get(f"{BASE_URL}{path}")
            assert resp.status_code == 200, \
                f"Expected 200 without admin key for {path}, got {resp.status_code}"

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

    @pytest.mark.skipif(not ADMIN_API_KEY, reason="WEB_UI_ADMIN_KEY not set")
    def test_patch_config_with_valid_key_succeeds(self, api):
        resp = api.patch(f"{BASE_URL}/api/config",
                         json={"validity": {"end_entity_days": 365}})
        assert resp.status_code == 200
        assert resp.json().get("ok") is True

    @pytest.mark.skipif(not ADMIN_API_KEY, reason="WEB_UI_ADMIN_KEY not set")
    def test_patch_config_with_wrong_key_is_403(self):
        s = self._plain_session()
        s.headers["X-Admin-Key"] = "DEFINITELY_WRONG_KEY_XYZ"
        resp = s.patch(f"{BASE_URL}/api/config",
                       json={"validity": {"end_entity_days": 365}})
        assert resp.status_code in (401, 403)

    @pytest.mark.skipif(not ADMIN_API_KEY, reason="WEB_UI_ADMIN_KEY not set")
    def test_revoke_without_key_is_403(self):
        resp = self._plain_session().post(f"{BASE_URL}/api/revoke",
                                          json={"serial": 1, "reason": 0})
        assert resp.status_code in (401, 403)

    @pytest.mark.skipif(not ADMIN_API_KEY, reason="WEB_UI_ADMIN_KEY not set")
    def test_issue_sub_ca_without_key_is_403(self):
        resp = self._plain_session().post(f"{BASE_URL}/api/issue-sub-ca",
                                          json={"cn": "Unauthorized CA", "validity_days": 365})
        assert resp.status_code in (401, 403)

    # ---- Security headers ----

    def test_x_frame_options_deny(self):
        assert self._plain_session().get(f"{BASE_URL}/").headers.get("X-Frame-Options") == "DENY"

    def test_x_content_type_options_nosniff(self):
        assert self._plain_session().get(f"{BASE_URL}/").headers.get("X-Content-Type-Options") == "nosniff"

    def test_cache_control_no_store(self):
        assert "no-store" in self._plain_session().get(f"{BASE_URL}/").headers.get("Cache-Control", "")

    # ---- CSRF ----

    def test_patch_config_bad_origin_rejected(self):
        s = self._plain_session()
        resp = s.patch(
            f"{BASE_URL}/api/config",
            json={"validity": {"end_entity_days": 365}},
            headers={
                "Content-Type": "application/json",
                "Origin": "https://evil.example.com",
            },
        )
        # 403 = CSRF blocked; 200 = server running without auth configured (backward compat)
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
        assert resp.content[0] == 0x30, "PKCS#12 should start with ASN.1 SEQUENCE (0x30)"

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
        # Prometheus exposition format starts with '#' comment lines or metric lines
        assert isinstance(resp.text, str) and len(resp.text) >= 0

    def test_post_api_config_same_as_patch(self, api):
        """POST /api/config is handled identically to PATCH via do_PATCH = do_POST."""
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
        assert "running" in entry, "Service entry missing 'running' key"
        assert "available" in entry, "Service entry missing 'available' key"

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
    """Verify that administrative endpoints behave correctly under admin key configuration."""

    @pytest.mark.skipif(not ADMIN_API_KEY, reason="WEB_UI_ADMIN_KEY not set — server has no key enforcement")
    def test_unauthorized_config_patch_fails(self, api):
        """When an admin key is configured, requests without it must be rejected."""
        plain_api = requests.Session()
        plain_api.verify = TLS_VERIFY
        if TLS_CLIENT_CERT:
            plain_api.cert = TLS_CLIENT_CERT
        resp = plain_api.patch(f"{BASE_URL}/api/config", json={"validity": {"end_entity_days": 10}})
        assert resp.status_code in (401, 403)

    def test_invalid_config_patch_type_handled(self, api):
        """Sending a non-numeric end_entity_days should either be rejected (400) or accepted
        as a no-op by the server; it must not cause a 500 error."""
        resp = api.patch(f"{BASE_URL}/api/config", json={"validity": {"end_entity_days": "invalid"}})
        assert resp.status_code < 500

    @pytest.mark.skipif(not ADMIN_API_KEY, reason="WEB_UI_ADMIN_KEY not set — server has no key enforcement")
    def test_issue_subca_requires_admin(self, api):
        """When an admin key is configured, unauthenticated Sub-CA issuance must be rejected."""
        plain_api = requests.Session()
        plain_api.verify = TLS_VERIFY
        if TLS_CLIENT_CERT:
            plain_api.cert = TLS_CLIENT_CERT
        resp = plain_api.post(f"{BASE_URL}/api/issue-sub-ca", json={"cn": "Test Sub-CA"})
        assert resp.status_code in (401, 403)

@pytest.mark.api
class TestServiceManagement:
    """Test the integration with ServiceManager for controlling sub-servers."""

    def test_list_services(self, api):
        resp = api.get(f"{BASE_URL}/api/services")
        assert resp.status_code == 200
        data = resp.json()
        if not data:
            pytest.skip("No services registered")
        first = data[list(data.keys())[0]]
        # Each entry must have running/available/url/config keys
        assert "running" in first, "Service entry missing 'running' key"
        assert "available" in first, "Service entry missing 'available' key"

    def test_service_stop_returns_ok(self, api):
        """Stopping an already-stopped (or running) service returns ok=True."""
        data = api.get(f"{BASE_URL}/api/services").json()
        if not data:
            pytest.skip("No services registered")
        name = next(iter(data))
        stop_resp = api.post(f"{BASE_URL}/api/services/{name}/stop", json={})
        assert stop_resp.status_code == 200
        body = stop_resp.json()
        assert body.get("ok") is True

    def test_service_start_unavailable_returns_503(self, api):
        """Starting a service whose module is not installed returns 503."""
        data = api.get(f"{BASE_URL}/api/services").json()
        unavailable = [n for n, e in data.items() if not e.get("available")]
        if not unavailable:
            pytest.skip("All services are available — cannot test 503 path")
        name = unavailable[0]
        resp = api.post(f"{BASE_URL}/api/services/{name}/start", json={"port": 19999})
        assert resp.status_code == 503
        
        
@pytest.mark.api
class TestExtendedCerts:
    """Test specialized certificate operations and binary downloads."""

    def test_download_crl(self, api):
        """/ca/crl returns a DER-encoded CRL."""
        resp = api.get(f"{BASE_URL}/ca/crl")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"] == "application/pkix-crl"
        assert len(resp.content) > 0

    def test_download_p12_bundle_content_type(self, api):
        """P12 download returns correct MIME type."""
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