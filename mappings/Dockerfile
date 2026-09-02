FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy engine codebase and mappings for validation
COPY src/ ./src/
COPY mappings/ ./mappings/

# Default entrypoint runs the mapping validator
ENTRYPOINT ["python", "mappings/validate_mappings.py"]
CMD ["mappings"]
