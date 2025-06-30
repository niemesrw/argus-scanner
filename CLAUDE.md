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

**⚠️ IMPORTANT: Always Use Virtual Environments**

Python development for this project requires a virtual environment to avoid dependency conflicts and ensure consistent behavior across different systems. This is especially important on macOS with Homebrew Python installations.

```bash
# Create and activate virtual environment (required for all Python work)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Verify you're in the virtual environment
which python  # Should show ./venv/bin/python
which pip     # Should show ./venv/bin/pip

# Install dependencies
pip install -r requirements.txt

# Install with development extras
pip install -e ".[dev]"

# Install test dependencies
pip install -r requirements-test.txt

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

# Deactivate virtual environment when done
deactivate
```

**Virtual Environment Best Practices:**
- Always activate the virtual environment before running any Python commands
- Never install packages globally with `--break-system-packages`
- Keep the `venv/` directory in `.gitignore` (already configured)
- Recreate the virtual environment if you encounter dependency issues:
  ```bash
  rm -rf venv
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt -r requirements-test.txt
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

## 🚨 CRITICAL: Pre-Push Testing Requirements

**BEFORE pushing any code to GitHub, you MUST run the comprehensive test suite to ensure code quality and prevent CI/CD failures.**

### Mandatory Pre-Push Checklist

**1. Code Quality Checks:**
```bash
# ALWAYS use virtual environment for Python development
source venv/bin/activate

# Format code with Black
black src/ tests/

# Lint with flake8 (must pass)
flake8 src/ tests/ --max-line-length=120 --max-complexity=10

# Type checking with mypy (must pass)
mypy src/ --ignore-missing-imports --no-strict-optional

# Security scanning (review results)
bandit -r src/ -f txt
```

**2. Complete Test Suite:**
```bash
# Ensure virtual environment is active
source venv/bin/activate

# Run ALL tests (must pass 100%)
pytest tests/ -v --cov=src --cov-report=html --cov-report=term

# Specific test categories (all must pass)
pytest tests/ -m "unit" -v --cov=src           # Unit tests
pytest tests/ -m "integration" -v              # Integration tests
pytest tests/ -m "security" -v                 # Security tests

# Performance benchmarks (for performance-related changes)
pytest tests/performance/benchmarks/ --benchmark-only
```

**3. Docker Build and Health Check:**
```bash
# Build Docker image locally
docker build -t argus-scanner:test .

# Test container startup and health
docker run -d --name argus-test -p 8080:8080 -e ARGUS_MOCK_MODE=true argus-scanner:test

# Wait and verify health endpoint
sleep 30
curl -f http://localhost:8080/health || (echo "Health check failed!" && exit 1)

# Clean up
docker stop argus-test && docker rm argus-test
```

**4. Local Deployment Test:**
```bash
# Test local deployment script
./scripts/deploy-local.sh development test

# Verify deployment
curl -f http://localhost:8080/health
curl -f http://localhost:8080/api/devices

# Clean up
cd deploy-development && ./stop.sh
```

**5. End-to-End Testing (for web changes):**
```bash
# Start application
docker-compose up -d

# Run E2E tests
pytest tests/e2e/ -v --html=e2e-report.html

# Clean up
docker-compose down
```

### Automated Pre-Push Script

Use the provided pre-push script to automate these checks:

```bash
# Make script executable (one time)
chmod +x scripts/pre-push-check.sh

# Run comprehensive checks before push
./scripts/pre-push-check.sh
```

### Minimum Coverage Requirements

- **Overall Coverage**: Minimum 80%
- **Unit Tests**: Must achieve >90% coverage for core modules
- **Integration Tests**: Must pass all scenarios
- **Security Tests**: Must pass all security validations
- **E2E Tests**: Must pass all user workflow tests

### When Tests Fail

**DO NOT push code if any of these fail:**

1. **Linting Errors**: Fix all flake8 and mypy issues
2. **Test Failures**: All tests must pass - no exceptions
3. **Coverage Drop**: Don't reduce overall coverage below 80%
4. **Security Issues**: Address all bandit security warnings
5. **Docker Build Fails**: Image must build successfully
6. **Health Checks Fail**: Application must start and respond properly

### Fast Development Workflow

For rapid development, use this minimal check before committing:

```bash
# Quick pre-commit checks (runs in ~30 seconds)
black src/ tests/                              # Format
flake8 src/ --select=E9,F63,F7,F82            # Critical errors only
pytest tests/ -m "unit and not slow" -x       # Fast unit tests only
```

### CI/CD Pipeline Integration

The GitHub Actions workflows will run the same checks:

- **ci-enhanced.yml**: Parallel test execution with coverage reporting
- **security.yml**: Comprehensive security scanning
- **deploy-docker.yml**: Docker deployment to staging/production

**If local tests pass, CI should pass too. If CI fails after local success, investigate environmental differences.**

### Emergency Hotfix Workflow

For critical production issues:

1. Create hotfix branch from main
2. Make minimal changes
3. Run critical tests only: `pytest tests/ -m "unit" -x --tb=short`
4. Test Docker build: `docker build -t argus-scanner:hotfix .`
5. Push and create immediate PR
6. Run full test suite in CI
7. Deploy after CI passes

### Test Fixtures and Utilities

The project includes comprehensive test fixtures in `tests/fixtures/`:

- **Database Fixtures**: `populate_test_database()` for realistic test data
- **Mock Services**: `vulnerable_network()` for testing scanning
- **Time Mocking**: `frozen_time()` for scheduler testing
- **Config Factory**: `config_factory` for environment testing

Use these fixtures extensively to create reliable, isolated tests.

## Deployment Workflows

### Local Development Deployment
```bash
# Quick local deployment for testing
./scripts/deploy-local.sh development

# Deploy specific version
./scripts/deploy-local.sh production v1.2.3
```

### Raspberry Pi Deployment
```bash
# Deploy to staging (via GitHub Actions)
gh workflow run deploy-docker.yml -f environment=staging

# Deploy to production (via GitHub Actions)
gh workflow run deploy-docker.yml -f environment=production -f version=v1.2.3
```

### Manual Raspberry Pi Deployment
```bash
# SSH to Raspberry Pi
ssh pi@your-pi-host

# Pull and run latest
docker pull ghcr.io/niemesrw/argus-scanner:main
docker run -d --name argus-scanner -p 8080:8080 \
  -e ARGUS_ENV=production \
  -e ARGUS_MOCK_MODE=false \
  -v argus_data:/app/data \
  ghcr.io/niemesrw/argus-scanner:main
```