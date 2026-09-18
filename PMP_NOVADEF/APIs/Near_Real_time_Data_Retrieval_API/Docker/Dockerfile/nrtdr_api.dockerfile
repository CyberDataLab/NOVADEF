FROM python:3.12-slim

WORKDIR /home/nrtdr_api

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    fastapi==0.115.6 \
    uvicorn[standard]==0.34.0 \
    redis[hiredis]==5.2.0 \
    websockets==14.1 \
    pydantic==2.10.3 \
    python-multipart==0.0.20


COPY APIs/Near_Real_time_Data_Retrieval_API/Scripts/api_server.py /home/nrtdr_api/
COPY APIs/Near_Real_time_Data_Retrieval_API/Docker/Entrypoint/entrypoint_api.py /home/nrtdr_api/
COPY APIs/Near_Real_time_Data_Retrieval_API/Scripts/nrtdr_api_logic.py /home/nrtdr_api/
# Create non-root user for security
RUN useradd -m -u 1000 redisapi && \
    chown -R redisapi:redisapi /home/nrtdr_api && \
    chmod +x /home/nrtdr_api/entrypoint_api.py

USER redisapi

# Default API port. The effective runtime port is driven by NRTDR_API_PORT.
EXPOSE 8001

ENTRYPOINT ["python3", "/home/nrtdr_api/entrypoint_api.py"]
