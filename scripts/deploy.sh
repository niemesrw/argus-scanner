#!/bin/bash
# Deployment script for Argus Scanner

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REGISTRY="${REGISTRY:-ghcr.io}"
IMAGE_NAME="${IMAGE_NAME:-argus-scanner}"
TAG="${TAG:-latest}"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_requirements() {
    log_info "Checking requirements..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check if running on ARM
    ARCH=$(uname -m)
    if [[ "$ARCH" == "aarch64" ]] || [[ "$ARCH" == "armv7l" ]]; then
        log_info "Detected ARM architecture: $ARCH"
    else
        log_warn "Not running on ARM architecture: $ARCH"
    fi
}

setup_directories() {
    log_info "Setting up directories..."
    
    mkdir -p data logs config
    chmod 755 data logs config
}

pull_image() {
    log_info "Pulling latest image..."
    
    docker pull "${REGISTRY}/${IMAGE_NAME}:${TAG}"
}

stop_containers() {
    log_info "Stopping existing containers..."
    
    if docker-compose ps -q | grep -q .; then
        docker-compose down
    else
        log_info "No running containers found"
    fi
}

start_containers() {
    log_info "Starting containers..."
    
    # Check if production override exists
    if [ -f "docker-compose.prod.yml" ]; then
        docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
    else
        docker-compose up -d
    fi
}

health_check() {
    log_info "Performing health check..."
    
    # Wait for container to start
    sleep 10
    
    # Check container status
    if docker-compose ps | grep -q "Up"; then
        log_info "Container is running"
    else
        log_error "Container failed to start"
        docker-compose logs
        exit 1
    fi
    
    # Check health endpoint
    if curl -f http://localhost:8080/health > /dev/null 2>&1; then
        log_info "Health check passed"
    else
        log_error "Health check failed"
        exit 1
    fi
}

cleanup() {
    log_info "Cleaning up old images..."
    
    docker image prune -f
}

# Main deployment flow
main() {
    log_info "Starting Argus Scanner deployment..."
    
    check_requirements
    setup_directories
    pull_image
    stop_containers
    start_containers
    health_check
    cleanup
    
    log_info "Deployment completed successfully!"
    log_info "Access the dashboard at: http://$(hostname -I | awk '{print $1}'):8080"
}

# Run main function
main "$@"