FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy anomaly detection script
COPY anomaly_detection.py .

# Entrypoint for running batch analysis on files
ENTRYPOINT ["python", "anomaly_detection.py"]
CMD ["--help"]
