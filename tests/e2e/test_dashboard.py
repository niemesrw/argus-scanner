"""
End-to-end tests for Argus Scanner Dashboard UI using Playwright
"""
import pytest
from playwright.sync_api import Page, expect
import requests
import time


class TestDashboard:
    """Test suite for the main dashboard functionality"""
    
    @pytest.fixture(autouse=True)
    def setup(self, page: Page):
        """Setup for each test - navigate to dashboard"""
        page.goto("http://localhost:8080")
        # Wait for page to load
        page.wait_for_load_state("networkidle")
    
    def test_dashboard_loads_successfully(self, page: Page):
        """Test that the dashboard page loads with correct title"""
        expect(page).to_have_title("Dashboard - Argus Scanner")
        expect(page.locator("h1")).to_contain_text("Network Security Dashboard")
    
    def test_navigation_menu_present(self, page: Page):
        """Test that all navigation menu items are present"""
        # Check brand
        expect(page.locator('a:has-text("Argus Scanner")')).to_be_visible()
        
        # Check navigation items
        expect(page.locator('a:has-text("Dashboard")')).to_be_visible()
        expect(page.locator('a:has-text("Devices")')).to_be_visible()
        expect(page.locator('a:has-text("Vulnerabilities")')).to_be_visible()
        expect(page.locator('a:has-text("Alerts")')).to_be_visible()
        expect(page.locator('a:has-text("Scans")')).to_be_visible()
    
    def test_statistics_cards_display(self, page: Page):
        """Test that all statistics cards are displayed with correct data"""
        # Total Devices card
        expect(page.locator('h6:has-text("Total Devices")')).to_be_visible()
        expect(page.locator('h3:has-text("3")')).to_be_visible()
        expect(page.locator('text=active')).to_be_visible()
        
        # Vulnerabilities card
        expect(page.locator('h6:has-text("Vulnerabilities")')).to_be_visible()
        expect(page.locator('text=critical')).to_be_visible()
        
        # Unresolved Alerts card
        expect(page.locator('h6:has-text("Unresolved Alerts")')).to_be_visible()
        expect(page.locator('text=Require attention')).to_be_visible()
        
        # Recent Scans card
        expect(page.locator('h6:has-text("Recent Scans")')).to_be_visible()
        expect(page.locator('text=Last 24 hours')).to_be_visible()
    
    def test_risk_distribution_section(self, page: Page):
        """Test that risk distribution section is present"""
        expect(page.locator('h5:has-text("Risk Distribution")')).to_be_visible()
        
        # Check for risk distribution chart canvas
        expect(page.locator('#riskChart')).to_be_visible()
    
    def test_recent_alerts_section(self, page: Page):
        """Test that recent alerts section is present"""
        expect(page.locator('h5:has-text("Recent Alerts")')).to_be_visible()
        expect(page.locator('text=No recent alerts')).to_be_visible()
    
    def test_high_risk_devices_table(self, page: Page):
        """Test that high risk devices table is present with headers"""
        expect(page.locator('h5:has-text("High Risk Devices")')).to_be_visible()
        expect(page.locator('a:has-text("View All")')).to_be_visible()
        
        # Check table headers
        expect(page.locator('th:has-text("Device")')).to_be_visible()
        expect(page.locator('th:has-text("IP Address")')).to_be_visible()
        expect(page.locator('th:has-text("OS")')).to_be_visible()
        expect(page.locator('th:has-text("Risk Score")')).to_be_visible()
        expect(page.locator('th:has-text("Vulnerabilities")')).to_be_visible()
        expect(page.locator('th:has-text("Last Seen")')).to_be_visible()
        
        # Check empty state
        expect(page.locator('text=No high risk devices found')).to_be_visible()
    
    def test_development_mode_indicator(self, page: Page):
        """Test that development mode indicator is visible"""
        expect(page.locator('text=development')).to_be_visible()
    
    def test_run_scan_button_present(self, page: Page):
        """Test that Run Scan button is present and clickable"""
        run_scan_button = page.locator('button:has-text("Run Scan")')
        expect(run_scan_button).to_be_visible()
        expect(run_scan_button).to_be_enabled()
    
    def test_footer_present(self, page: Page):
        """Test that footer is present"""
        expect(page.locator('text=Argus Scanner - Network Security Scanner')).to_be_visible()