"""
Pytest configuration for Argus Scanner E2E tests
"""
import pytest
from playwright.sync_api import Playwright, Browser, BrowserContext, Page
import requests
import time


def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """Configure browser context arguments"""
    return {
        **browser_context_args,
        "viewport": {"width": 1280, "height": 720},
        "ignore_https_errors": True,
    }


@pytest.fixture(scope="session", autouse=True)
def ensure_application_running():
    """Ensure the Argus application is running before tests"""
    max_attempts = 30
    for attempt in range(max_attempts):
        try:
            response = requests.get("http://localhost:8080", timeout=5)
            if response.status_code == 200:
                print("✓ Application is running and ready for tests")
                return
        except requests.exceptions.RequestException:
            if attempt < max_attempts - 1:
                print(f"Waiting for application to start... (attempt {attempt + 1}/{max_attempts})")
                time.sleep(2)
            else:
                pytest.exit("Application is not running on http://localhost:8080")


@pytest.fixture(scope="function")
def page(browser: Browser) -> Page:
    """Create a new page for each test"""
    context = browser.new_context()
    page = context.new_page()
    
    # Set longer timeout for slower operations
    page.set_default_timeout(10000)
    
    yield page
    
    context.close()


@pytest.fixture(scope="function")
def api_client():
    """HTTP client for API testing"""
    class APIClient:
        BASE_URL = "http://localhost:8080"
        
        def get(self, endpoint: str):
            return requests.get(f"{self.BASE_URL}{endpoint}")
        
        def post(self, endpoint: str, data=None, json=None):
            return requests.post(f"{self.BASE_URL}{endpoint}", data=data, json=json)
    
    return APIClient()