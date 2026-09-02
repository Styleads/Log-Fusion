FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    MAPPINGS_DIR=/app/mappings \
    STORAGE_API_URL=http://storage-api:8000

WORKDIR /app

# Install curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code, mappings, and tests
COPY src/ ./src/
COPY mappings/ ./mappings/
COPY tests/ ./tests/

# Expose Engine API port
EXPOSE 8001

# Health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

# Default command: run FastAPI server
CMD ["uvicorn", "src.app.main2:app", "--host", "0.0.0.0", "--port", "8001"]
