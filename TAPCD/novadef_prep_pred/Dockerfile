FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Código y recursos (models/, high/, GeoLite2-*.mmdb, etc.)
COPY . .

ENV PYTHONUNBUFFERED=1

