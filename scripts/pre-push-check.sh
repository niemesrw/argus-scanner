#!/bin/bash
set -e

# Argus Scanner Pre-Push Validation Script
# Run this script before pushing code to GitHub to ensure quality

echo "🚀 Argus Scanner Pre-Push Validation"
echo "====================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Variables to track failures
FAILURES=0
WARNINGS=0
START_TIME=$(date +%s)

# Check prerequisites
echo ""
print_status "Checking prerequisites..."

if ! command_exists python3; then
    print_error "Python 3 is required but not installed"
    exit 1
fi

if ! command_exists docker; then
    print_error "Docker is required but not installed"
    exit 1
fi

if ! python3 -c "import pytest" 2>/dev/null; then
    print_error "pytest is not installed. Run: pip install -r requirements-test.txt"
    exit 1
fi

print_success "Prerequisites check passed"

# 1. Code Formatting and Linting
echo ""
print_status "Step 1: Code Quality Checks"
echo "----------------------------"

# Black formatting
print_status "Running Black formatter..."
if command_exists black; then
    if black --check src/ tests/ 2>/dev/null; then
        print_success "Code formatting is correct"
    else
        print_warning "Code formatting issues found. Running Black formatter..."
        black src/ tests/
        print_success "Code has been formatted"
    fi
else
    print_warning "Black not installed. Install with: pip install black"
    ((WARNINGS++))
fi

# Flake8 linting
print_status "Running flake8 linter..."
if command_exists flake8; then
    if flake8 src/ tests/ --max-line-length=120 --max-complexity=10 --statistics --count 2>/dev/null; then
        print_success "Linting passed"
    else
        print_error "Linting failed. Please fix the issues above."
        ((FAILURES++))
    fi
else
    print_warning "flake8 not installed. Install with: pip install flake8"
    ((WARNINGS++))
fi

# MyPy type checking
print_status "Running mypy type checker..."
if command_exists mypy; then
    if mypy src/ --ignore-missing-imports --no-strict-optional 2>/dev/null; then
        print_success "Type checking passed"
    else
        print_warning "Type checking found issues (non-blocking)"
        ((WARNINGS++))
    fi
else
    print_warning "mypy not installed. Install with: pip install mypy"
    ((WARNINGS++))
fi

# Security scanning with bandit
print_status "Running security scan..."
if command_exists bandit; then
    if bandit -r src/ -f txt --severity-level medium --quiet 2>/dev/null; then
        print_success "Security scan passed"
    else
        print_warning "Security issues found. Please review bandit output."
        bandit -r src/ -f txt --severity-level medium 2>/dev/null || true
        ((WARNINGS++))
    fi
else
    print_warning "bandit not installed. Install with: pip install bandit"
    ((WARNINGS++))
fi

# 2. Test Suite
echo ""
print_status "Step 2: Running Test Suite"
echo "--------------------------"

# Unit tests
print_status "Running unit tests..."
if pytest tests/ -m "unit and not slow" -q --tb=short --cov=src --cov-fail-under=80 2>/dev/null; then
    print_success "Unit tests passed"
else
    print_error "Unit tests failed"
    ((FAILURES++))
fi

# Integration tests
print_status "Running integration tests..."
if pytest tests/ -m "integration" -q --tb=short 2>/dev/null; then
    print_success "Integration tests passed"
else
    print_error "Integration tests failed"
    ((FAILURES++))
fi

# Security tests
print_status "Running security tests..."
if pytest tests/ -m "security" -q --tb=short 2>/dev/null; then
    print_success "Security tests passed"
else
    print_error "Security tests failed"
    ((FAILURES++))
fi

# Quick smoke test of all tests
print_status "Running quick smoke test of all tests..."
if pytest tests/ --tb=no -q --maxfail=5 --ignore=tests/e2e/ --ignore=tests/performance/ -x 2>/dev/null; then
    print_success "Full test suite smoke test passed"
else
    print_error "Some tests are failing. Run full test suite for details."
    ((FAILURES++))
fi

# 3. Docker Build Test
echo ""
print_status "Step 3: Docker Build Validation"
echo "-------------------------------"

print_status "Building Docker image..."
if docker build -t argus-scanner:pre-push-test -f docker/Dockerfile . >/dev/null 2>&1; then
    print_success "Docker build successful"
    
    # Test container startup
    print_status "Testing container startup..."
    if docker run -d --name argus-pre-push-test -p 18080:8080 \
        -e ARGUS_MOCK_MODE=true \
        -e ARGUS_ENV=testing \
        argus-scanner:pre-push-test >/dev/null 2>&1; then
        
        # Wait for container to start
        sleep 15
        
        # Health check
        if curl -f -s http://localhost:18080/health >/dev/null 2>&1; then
            print_success "Container health check passed"
        else
            print_error "Container health check failed"
            ((FAILURES++))
        fi
        
        # Cleanup
        docker stop argus-pre-push-test >/dev/null 2>&1 || true
        docker rm argus-pre-push-test >/dev/null 2>&1 || true
    else
        print_error "Container startup failed"
        ((FAILURES++))
    fi
    
    # Cleanup image
    docker rmi argus-scanner:pre-push-test >/dev/null 2>&1 || true
else
    print_error "Docker build failed"
    ((FAILURES++))
fi

# 4. Documentation and Configuration Check
echo ""
print_status "Step 4: Documentation and Configuration"
echo "--------------------------------------"

# Check if important files exist
REQUIRED_FILES=(
    "README.md"
    "CLAUDE.md"
    "requirements.txt"
    "requirements-test.txt"
    "docker/Dockerfile"
    "docker-compose.yml"
    "pytest.ini"
    ".coveragerc"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        print_success "Found $file"
    else
        print_warning "Missing $file"
        ((WARNINGS++))
    fi
done

# Check for common issues
print_status "Checking for common issues..."

# Check for hardcoded secrets
if grep -r "password.*=" src/ --include="*.py" | grep -v "password_field\|password_hash" | head -5; then
    print_warning "Potential hardcoded passwords found"
    ((WARNINGS++))
else
    print_success "No obvious hardcoded passwords found"
fi

# Check for debug statements
if grep -r "print(" src/ --include="*.py" | head -5; then
    print_warning "Debug print statements found in source code"
    ((WARNINGS++))
else
    print_success "No debug print statements found"
fi

# 5. Coverage Report
echo ""
print_status "Step 5: Coverage Report"
echo "----------------------"

print_status "Generating coverage report..."
if pytest tests/ --cov=src --cov-report=term-missing --cov-fail-under=80 -q 2>/dev/null | tail -10; then
    print_success "Coverage requirements met (≥80%)"
else
    print_error "Coverage below 80% threshold"
    ((FAILURES++))
fi

# Summary
echo ""
echo "======================================="
print_status "Pre-Push Validation Summary"
echo "======================================="

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo "Duration: ${DURATION}s"
echo "Failures: $FAILURES"
echo "Warnings: $WARNINGS"

if [[ $FAILURES -eq 0 ]]; then
    echo ""
    print_success "🎉 All critical checks passed! Code is ready to push."
    
    if [[ $WARNINGS -gt 0 ]]; then
        print_warning "⚠️  $WARNINGS warnings found. Consider addressing them."
    fi
    
    echo ""
    echo "Next steps:"
    echo "  1. git add ."
    echo "  2. git commit -m \"Your commit message\""
    echo "  3. git push"
    
    exit 0
else
    echo ""
    print_error "❌ $FAILURES critical issues found. DO NOT PUSH until fixed."
    
    echo ""
    echo "To fix issues:"
    echo "  1. Address all FAIL items above"
    echo "  2. Run this script again"
    echo "  3. Only push when all checks pass"
    
    exit 1
fi