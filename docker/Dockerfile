# Multi-stage, multi-architecture Dockerfile for Argus Scanner
# Supports linux/amd64, linux/arm64, darwin/arm64

FROM --platform=$BUILDPLATFORM python:3.11-slim AS builder

# Build arguments for cross-compilation
ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libssl-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.11-slim

# Install runtime dependencies including nmap
RUN apt-get update && apt-get install -y \
    nmap \
    libssl3 \
    libffi8 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 argus && \
    mkdir -p /app/data /app/logs && \
    chown -R argus:argus /app

WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=argus:argus . .

# Switch to non-root user
USER argus

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    ARGUS_ENV=production \
    ARGUS_DB_PATH=/app/data/argus.db \
    ARGUS_LOG_PATH=/app/logs

# Expose web dashboard port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Entry point
CMD ["python", "-m", "src.main"]