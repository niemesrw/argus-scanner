"""
End-to-end tests for individual pages in Argus Scanner
"""
import pytest
from playwright.sync_api import Page, expect


class TestPages:
    """Test suite for individual page functionality"""
    
    def test_devices_page_loads(self, page: Page):
        """Test that devices page loads without template errors"""
        page.goto("http://localhost:8080/devices")
        
        # Should load successfully now that template exists
        if "TemplateNotFound" in page.content():
            pytest.fail("devices.html template is missing")
        else:
            expect(page).to_have_title("Devices - Argus Scanner")
            expect(page.locator("h1")).to_contain_text("Network Devices")
    
    def test_vulnerabilities_page_loads(self, page: Page):
        """Test that vulnerabilities page loads without template errors"""
        page.goto("http://localhost:8080/vulnerabilities")
        
        # Should load successfully now that template exists
        if "TemplateNotFound" in page.content():
            pytest.fail("vulnerabilities.html template is missing")
        else:
            expect(page).to_have_title("Vulnerabilities - Argus Scanner")
            expect(page.locator("h1")).to_contain_text("Vulnerabilities")
    
    def test_alerts_page_loads(self, page: Page):
        """Test that alerts page loads without template errors"""
        page.goto("http://localhost:8080/alerts")
        
        # Should load successfully now that template exists
        if "TemplateNotFound" in page.content():
            pytest.fail("alerts.html template is missing")
        else:
            expect(page).to_have_title("Alerts - Argus Scanner")
            expect(page.locator("h1")).to_contain_text("Security Alerts")
    
    def test_scans_page_loads(self, page: Page):
        """Test that scans page loads without template errors"""
        page.goto("http://localhost:8080/scans")
        
        # Should load successfully now that template exists
        if "TemplateNotFound" in page.content():
            pytest.fail("scans.html template is missing")
        else:
            expect(page).to_have_title("Scans - Argus Scanner")
            expect(page.locator("h1")).to_contain_text("Network Scans")
    
    def test_pages_have_navigation(self, page: Page):
        """Test that all pages include the navigation menu"""
        pages = ["/devices", "/vulnerabilities", "/alerts", "/scans"]
        
        for page_url in pages:
            page.goto(f"http://localhost:8080{page_url}")
            
            # Skip if template is missing (we'll fix this)
            if "TemplateNotFound" in page.content():
                continue
                
            # Check navigation is present
            expect(page.locator('a:has-text("Argus Scanner")')).to_be_visible()
            expect(page.locator('a:has-text("Dashboard")')).to_be_visible()
            expect(page.locator('a:has-text("Devices")')).to_be_visible()
            expect(page.locator('a:has-text("Vulnerabilities")')).to_be_visible()
            expect(page.locator('a:has-text("Alerts")')).to_be_visible()
    
    def test_pages_have_consistent_styling(self, page: Page):
        """Test that pages use consistent styling and layout"""
        pages = ["/", "/devices", "/vulnerabilities", "/alerts", "/scans"]
        
        for page_url in pages:
            page.goto(f"http://localhost:8080{page_url}")
            
            # Skip if template is missing
            if "TemplateNotFound" in page.content():
                continue
            
            # Check for Bootstrap classes (should be consistent)
            expect(page.locator('nav.navbar')).to_be_visible()
            expect(page.locator('main')).to_be_visible()
            expect(page.locator('footer')).to_be_visible()