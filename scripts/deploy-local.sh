#!/bin/bash
set -e

# Local deployment script for Argus Scanner
# Usage: ./scripts/deploy-local.sh [environment] [version]

ENVIRONMENT=${1:-development}
VERSION=${2:-main}
REGISTRY="ghcr.io"
IMAGE_NAME="niemesrw/argus-scanner"
COMPOSE_PROJECT_NAME="argus-${ENVIRONMENT}"

echo "🚀 Deploying Argus Scanner locally"
echo "Environment: $ENVIRONMENT"
echo "Version: $VERSION"
echo "Project: $COMPOSE_PROJECT_NAME"

# Create deployment directory
DEPLOY_DIR="./deploy-$ENVIRONMENT"
mkdir -p "$DEPLOY_DIR"

# Create docker-compose file for local deployment
cat > "$DEPLOY_DIR/docker-compose.yml" << EOF
version: '3.8'

services:
  argus:
    image: $REGISTRY/$IMAGE_NAME:$VERSION
    container_name: argus-scanner-$ENVIRONMENT
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - ARGUS_ENV=$ENVIRONMENT
      - ARGUS_MOCK_MODE=\${ARGUS_MOCK_MODE:-true}
      - ARGUS_LOG_LEVEL=\${ARGUS_LOG_LEVEL:-DEBUG}
      - ARGUS_NETWORK_RANGE=\${ARGUS_NETWORK_RANGE:-192.168.1.0/24}
      - ARGUS_SECRET_KEY=\${ARGUS_SECRET_KEY:-dev-secret-key-change-me}
      - ARGUS_DATABASE_URL=sqlite:///app/data/argus-$ENVIRONMENT.db
      - ARGUS_ENABLE_EMAIL_ALERTS=\${ARGUS_ENABLE_EMAIL_ALERTS:-false}
      - ARGUS_SMTP_HOST=\${ARGUS_SMTP_HOST:-}
      - ARGUS_SMTP_PORT=\${ARGUS_SMTP_PORT:-587}
      - ARGUS_SMTP_USERNAME=\${ARGUS_SMTP_USERNAME:-}
      - ARGUS_SMTP_PASSWORD=\${ARGUS_SMTP_PASSWORD:-}
      - ARGUS_ALERT_FROM=\${ARGUS_ALERT_FROM:-}
      - ARGUS_ALERT_TO=\${ARGUS_ALERT_TO:-}
      - ARGUS_SLACK_WEBHOOK=\${ARGUS_SLACK_WEBHOOK:-}
      - ARGUS_SCAN_INTERVAL=\${ARGUS_SCAN_INTERVAL:-600}
    volumes:
      - argus_data_$ENVIRONMENT:/app/data
      - argus_logs_$ENVIRONMENT:/app/logs
    networks:
      - argus_network
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # Optional: Add vulnerable test services for development
  test-services:
    profiles: ["testing"]
    image: vulnerables/web-dvwa
    container_name: argus-test-services-$ENVIRONMENT
    ports:
      - "8081:80"
    networks:
      - argus_network

networks:
  argus_network:
    driver: bridge
    name: argus_network_$ENVIRONMENT

volumes:
  argus_data_$ENVIRONMENT:
    name: argus_data_$ENVIRONMENT
  argus_logs_$ENVIRONMENT:
    name: argus_logs_$ENVIRONMENT
EOF

# Create environment file
cat > "$DEPLOY_DIR/.env" << EOF
# Argus Scanner Configuration for $ENVIRONMENT
ARGUS_MOCK_MODE=true
ARGUS_LOG_LEVEL=DEBUG
ARGUS_NETWORK_RANGE=192.168.1.0/24
ARGUS_SECRET_KEY=dev-secret-key-change-me
ARGUS_SCAN_INTERVAL=600

# Email Alert Configuration (optional)
ARGUS_ENABLE_EMAIL_ALERTS=false
ARGUS_SMTP_HOST=
ARGUS_SMTP_PORT=587
ARGUS_SMTP_USERNAME=
ARGUS_SMTP_PASSWORD=
ARGUS_ALERT_FROM=argus@example.com
ARGUS_ALERT_TO=admin@example.com

# Slack Integration (optional)
ARGUS_SLACK_WEBHOOK=

# Development settings
COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME
EOF

# Create management scripts
cat > "$DEPLOY_DIR/start.sh" << EOF
#!/bin/bash
echo "Starting Argus Scanner ($ENVIRONMENT)..."
docker-compose up -d
echo "Argus Scanner is starting up..."
echo "Dashboard will be available at: http://localhost:8080"
echo "Check status: docker-compose ps"
echo "View logs: docker-compose logs -f"
EOF

cat > "$DEPLOY_DIR/stop.sh" << EOF
#!/bin/bash
echo "Stopping Argus Scanner ($ENVIRONMENT)..."
docker-compose down
echo "Stopped."
EOF

cat > "$DEPLOY_DIR/restart.sh" << EOF
#!/bin/bash
echo "Restarting Argus Scanner ($ENVIRONMENT)..."
docker-compose down
docker-compose up -d
echo "Restarted."
EOF

cat > "$DEPLOY_DIR/logs.sh" << EOF
#!/bin/bash
docker-compose logs -f argus
EOF

cat > "$DEPLOY_DIR/update.sh" << EOF
#!/bin/bash
VERSION=\${1:-main}
echo "Updating to version: \$VERSION"
docker-compose down
docker pull $REGISTRY/$IMAGE_NAME:\$VERSION
sed -i "s|$REGISTRY/$IMAGE_NAME:.*|$REGISTRY/$IMAGE_NAME:\$VERSION|" docker-compose.yml
docker-compose up -d
echo "Updated to \$VERSION"
EOF

cat > "$DEPLOY_DIR/backup.sh" << EOF
#!/bin/bash
set -e

BACKUP_DIR="./backups"
TIMESTAMP=\$(date +%Y%m%d_%H%M%S)

mkdir -p \$BACKUP_DIR

echo "Creating backup at \$TIMESTAMP"

# Backup database
docker exec argus-scanner-$ENVIRONMENT sqlite3 /app/data/argus-$ENVIRONMENT.db ".backup /app/data/argus_backup_\$TIMESTAMP.db" || true
docker cp argus-scanner-$ENVIRONMENT:/app/data/argus_backup_\$TIMESTAMP.db \$BACKUP_DIR/ || true

# Backup environment and config
cp .env \$BACKUP_DIR/env_\$TIMESTAMP
cp docker-compose.yml \$BACKUP_DIR/compose_\$TIMESTAMP.yml

echo "Backup completed: \$BACKUP_DIR"
EOF

# Make scripts executable
chmod +x "$DEPLOY_DIR"/*.sh

echo ""
echo "✅ Deployment files created in $DEPLOY_DIR"
echo ""

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Pull the image
echo "📥 Pulling image: $REGISTRY/$IMAGE_NAME:$VERSION"
if ! docker pull "$REGISTRY/$IMAGE_NAME:$VERSION"; then
    echo "❌ Failed to pull image. Building locally..."
    docker build -t "$REGISTRY/$IMAGE_NAME:$VERSION" .
fi

# Stop existing container if running
EXISTING_CONTAINER="argus-scanner-$ENVIRONMENT"
if docker ps -a --format '{{.Names}}' | grep -q "^$EXISTING_CONTAINER$"; then
    echo "🛑 Stopping existing container: $EXISTING_CONTAINER"
    docker stop "$EXISTING_CONTAINER" >/dev/null 2>&1 || true
    docker rm "$EXISTING_CONTAINER" >/dev/null 2>&1 || true
fi

# Deploy
cd "$DEPLOY_DIR"
echo "🚀 Starting deployment..."
docker-compose up -d

# Wait for service to be ready
echo "⏳ Waiting for service to be ready..."
for i in {1..30}; do
    if curl -f -s http://localhost:8080/health >/dev/null 2>&1; then
        echo "✅ Service is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ Service failed to start properly"
        echo "Check logs with: cd $DEPLOY_DIR && ./logs.sh"
        exit 1
    fi
    sleep 2
done

echo ""
echo "🎉 Deployment successful!"
echo ""
echo "📊 Dashboard: http://localhost:8080"
echo "🩺 Health check: http://localhost:8080/health"
echo "📁 Management scripts: $DEPLOY_DIR/"
echo ""
echo "Useful commands:"
echo "  View logs:    cd $DEPLOY_DIR && ./logs.sh"
echo "  Stop:         cd $DEPLOY_DIR && ./stop.sh"
echo "  Restart:      cd $DEPLOY_DIR && ./restart.sh"
echo "  Update:       cd $DEPLOY_DIR && ./update.sh [version]"
echo "  Backup:       cd $DEPLOY_DIR && ./backup.sh"
echo ""

# Show container status
docker-compose ps