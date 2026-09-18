FROM python:3.12-slim

# Set working directory
WORKDIR /home/redis_worker

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    librdkafka-dev \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    confluent-kafka==2.6.0 \
    redis==5.2.0 \
    pymongo==4.10.1

COPY Databases_module/Scripts/kafka_redis_worker.py /home/redis_worker/
COPY Databases_module/Scripts/worker_kafka_bootstrap_helpers.py /home/redis_worker/
COPY Databases_module/Scripts/worker_payload_helpers.py /home/redis_worker/
COPY Databases_module/Docker/Entrypoints/entrypoint_worker.py /home/redis_worker/

# Create non-root user for security
RUN useradd -m -u 1000 redisworker && \
    chown -R redisworker:redisworker /home/redis_worker && \
    chmod +x /home/redis_worker/entrypoint_worker.py

USER redisworker

ENTRYPOINT ["python3", "/home/redis_worker/entrypoint_worker.py"]
