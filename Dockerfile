FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend and website
COPY backend/ ./backend/
COPY website/ ./website/

ENV PORT=8000
ENV HOST=0.0.0.0
EXPOSE 8000

CMD ["python", "backend/main.py"]
