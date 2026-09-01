FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    OLLAMA_BASE_URL=http://localhost:11434

WORKDIR /app

# Install curl and any basic dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and default directories
COPY src/ ./src/
COPY documents/ ./documents/
COPY vectorstore/ ./vectorstore/

# Default command to run the interactive RAG Chatbot CLI
CMD ["python", "src/main.py"]
