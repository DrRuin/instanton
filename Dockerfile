# ============================================================================
# Instanton - Production Dockerfile
# Multi-stage build for minimal image size
# ============================================================================

# Stage 1: Build dependencies
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Stage 2: Production image
FROM python:3.11-slim AS production

# Labels
LABEL org.opencontainers.image.title="Instanton"
LABEL org.opencontainers.image.description="Tunnel through barriers, instantly"
LABEL org.opencontainers.image.vendor="Instanton Project"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/DrRuin/instanton"

# Create non-root user
RUN groupadd -r instanton && useradd -r -g instanton instanton

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code (for reference/debugging, package already installed in venv)
COPY src/ ./src/

# Switch to non-root user
USER instanton

# Default environment variables
ENV INSTANTON_SERVER="instanton.tech:443"
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import instanton; print('healthy')" || exit 1

# Default command (tunnel client)
ENTRYPOINT ["instanton"]
CMD ["--help"]
