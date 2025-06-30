# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Argus is a network security scanner designed for continuous monitoring of network devices and vulnerability detection. It's built for authorized security testing only and features a defensive security architecture.

**Core Architecture:**
- Python Flask web application with SQLAlchemy database
- Modular design with separate components for scanning, alerting, and web dashboard
- Containerized deployment with Docker support for both development and production
- Scheduler-based continuous monitoring with configurable intervals

**Key Components:**
- `src/scanner/`: Network discovery and vulnerability scanning modules
- `src/web/`: Flask web application and dashboard
- `src/database/`: SQLAlchemy models and database management
- `src/alerts/`: Email and Slack notification system
- `src/scheduler/`: APScheduler-based task management
- `src/config/`: Environment-based configuration management

## Development Commands

### Local Development
```bash
# Start development environment with mock mode
docker-compose up -d

# Access dashboard at http://localhost:8080

# Start with vulnerable test services
docker-compose --profile testing up -d
```

### Python Development
```bash
# Install dependencies
pip install -r requirements.txt

# Install with development extras
pip install -e ".[dev]"

# Run fast unit tests only (for CI)
pytest tests/ -v --cov=src --ignore=tests/e2e/ --ignore=tests/performance/

# Run all tests including E2E (slow)
pytest tests/ -v --cov=src

# Run specific test categories
pytest tests/ -m "unit" -v          # Unit tests only
pytest tests/ -m "e2e" -v           # E2E tests only
pytest tests/ -m "integration" -v   # Integration tests only

# Code formatting and linting
black src/ tests/
flake8 src/ tests/
mypy src/
```

### Manual Execution
```bash
# Run scanner directly
python -m src.main

# Or using entry point (after pip install)
argus-scanner
```

## Environment Configuration

The application uses environment variables for configuration (see `src/config/settings.py`):

**Essential Development Variables:**
- `ARGUS_ENV=development` - Enables debug mode
- `ARGUS_MOCK_MODE=true` - Uses mock data instead of real network scans
- `ARGUS_NETWORK_RANGE=192.168.1.0/24` - Target network range
- `ARGUS_SCAN_INTERVAL=300` - Scan frequency in seconds

**Security Settings:**
- `ARGUS_ENABLE_EXPLOIT_TESTING=false` - Never enable in production
- `ARGUS_AUTHORIZED_NETWORKS` - Comma-separated list of authorized scan targets

## Mock Mode for Safe Development

When `ARGUS_MOCK_MODE=true`, the scanner generates fake network data instead of performing real scans. This is essential for development to avoid unintended network scanning.

## Database

- SQLite database located at `/app/data/argus.db` (configurable)
- Database initialization handled in `src/database/models.py:init_db()`
- Flask-Migrate for schema migrations

## Security Notes

This is a defensive security tool designed for authorized network monitoring only. When working with this codebase:

1. Always use mock mode during development
2. Never enable exploit testing features
3. Ensure proper network authorization before deployment
4. All scanning activities are logged for audit purposes

## Testing Infrastructure

### GitHub Actions Workflows

**Fast CI Pipeline (.github/workflows/ci.yml):**
- Runs on every push and pull request
- Executes unit and integration tests only (skips E2E and performance)
- Includes linting, type checking, security scans, and Docker builds
- Optimized for speed to provide quick feedback

**E2E and Performance Tests (.github/workflows/e2e.yml):**
- Runs nightly or manually triggered
- Includes comprehensive Playwright E2E tests
- Performance testing with load scenarios
- Only runs on web-related changes or when manually triggered

### End-to-End Testing with Playwright

**For Claude Code Development:**
When working on web-related features or testing, always use the Playwright MCP server tools instead of writing traditional Playwright test files. This provides direct browser automation capabilities through the following MCP tools:

- `mcp__playwright__browser_navigate` - Navigate to URLs
- `mcp__playwright__browser_snapshot` - Capture page state for analysis
- `mcp__playwright__browser_click` - Click elements
- `mcp__playwright__browser_type` - Fill forms and input fields
- `mcp__playwright__browser_take_screenshot` - Visual verification
- Additional browser automation tools for comprehensive testing

Start the application with `docker-compose up -d` and use these MCP tools to interact with the dashboard at http://localhost:8080.

**Documentation and API References:**
For up-to-date library documentation and API references, use the Context7 MCP server tools:

- `mcp__context7__resolve-library-id` - Find the correct library ID for any package/framework
- `mcp__context7__get-library-docs` - Fetch current documentation for libraries used in the project

This is especially useful for Flask, SQLAlchemy, APScheduler, and other Python libraries to ensure you're using current best practices and APIs.

**Traditional Playwright Testing:**
```bash
# Install test dependencies
pip install -r requirements-test.txt
playwright install

# Run all E2E tests
pytest tests/e2e/ -v

# Run specific test categories
pytest tests/e2e/test_api.py -v          # API endpoint tests
pytest tests/e2e/test_dashboard.py -v    # Dashboard UI tests
pytest tests/e2e/test_navigation.py -v   # Navigation tests
pytest tests/e2e/test_pages.py -v        # Individual page tests
```

### Mock Vulnerable Services
The project includes mock vulnerable services in docker-compose for testing:
- `vulnerables/web-dvwa` - Web application with known vulnerabilities
- `rastasheep/ubuntu-sshd` - SSH service for testing

Access via: `docker-compose --profile testing up -d`

### Test Structure
- `tests/e2e/` - Playwright end-to-end tests
- `tests/e2e/conftest.py` - Pytest configuration and fixtures
- `pytest.ini` - Test configuration
- `requirements-test.txt` - Test dependencies