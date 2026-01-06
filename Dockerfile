# ============================================================================
# Tachyon - Production Dockerfile
# Multi-stage build for minimal image size
# ============================================================================

# Stage 1: Build dependencies
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Stage 2: Production image
FROM python:3.11-slim as production

# Labels
LABEL org.opencontainers.image.title="Tachyon"
LABEL org.opencontainers.image.description="Faster-than-light tunneling"
LABEL org.opencontainers.image.vendor="Tachyon Project"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/DrRuin/tachyon"

# Create non-root user
RUN groupadd -r tachyon && useradd -r -g tachyon tachyon

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY src/ ./src/
COPY pyproject.toml .

# Install the package
RUN pip install --no-cache-dir -e .

# Switch to non-root user
USER tachyon

# Default environment variables
ENV TACHYON_SERVER="tachyon.dev:443"
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import tachyon; print('healthy')" || exit 1

# Default command (tunnel client)
ENTRYPOINT ["tachyon"]
CMD ["--help"]
