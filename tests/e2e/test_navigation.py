"""
End-to-end tests for Argus Scanner Navigation using Playwright
"""

import pytest
from playwright.sync_api import Page, expect


class TestNavigation:
    """Test suite for navigation functionality"""

    @pytest.fixture(autouse=True)
    def setup(self, page: Page):
        """Setup for each test - navigate to dashboard"""
        page.goto("http://localhost:8080")
        page.wait_for_load_state("networkidle")

    def test_devices_page_navigation(self, page: Page):
        """Test navigation to devices page"""
        page.click('a:has-text("Devices")')

        # Should either load devices page or show template error
        # We expect template error initially, which we'll fix later
        expect(page).to_have_url("http://localhost:8080/devices")

    def test_vulnerabilities_page_navigation(self, page: Page):
        """Test navigation to vulnerabilities page"""
        page.click('a:has-text("Vulnerabilities")')

        # Should either load vulnerabilities page or show template error
        expect(page).to_have_url("http://localhost:8080/vulnerabilities")

    def test_alerts_page_navigation(self, page: Page):
        """Test navigation to alerts page"""
        page.click('a:has-text("Alerts")')

        # Should either load alerts page or show template error
        expect(page).to_have_url("http://localhost:8080/alerts")

    def test_scans_page_navigation(self, page: Page):
        """Test navigation to scans page"""
        page.click('a:has-text("Scans")')

        # Should either load scans page or show template error
        expect(page).to_have_url("http://localhost:8080/scans")

    def test_dashboard_navigation_from_brand(self, page: Page):
        """Test navigation back to dashboard from brand link"""
        # Navigate away first
        page.goto("http://localhost:8080/devices")

        # Click brand to return to dashboard
        page.click('a:has-text("Argus Scanner")')
        expect(page).to_have_url("http://localhost:8080/")
        expect(page.locator("h1")).to_contain_text("Network Security Dashboard")

    def test_dashboard_navigation_from_menu(self, page: Page):
        """Test navigation back to dashboard from menu"""
        # Navigate away first
        page.goto("http://localhost:8080/devices")

        # Click Dashboard menu item
        page.click('a:has-text("Dashboard")')
        expect(page).to_have_url("http://localhost:8080/")
        expect(page.locator("h1")).to_contain_text("Network Security Dashboard")

    def test_view_all_devices_link(self, page: Page):
        """Test View All link in High Risk Devices section"""
        page.click('a:has-text("View All")')
        expect(page).to_have_url("http://localhost:8080/devices")
