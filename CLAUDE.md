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

# Run tests
pytest tests/ -v --cov=src

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

### End-to-End Testing with Playwright
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