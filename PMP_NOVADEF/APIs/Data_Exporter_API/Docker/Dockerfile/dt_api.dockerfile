FROM python:3.12-slim

WORKDIR /home/dt_api

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    fastapi==0.115.6 \
    uvicorn[standard]==0.34.0 \
    httpx==0.28.1 \
    pydantic==2.10.3 \
    python-multipart==0.0.20

COPY APIs/Data_Exporter_API/Scripts/dt_config.py /home/dt_api/
COPY APIs/Data_Exporter_API/Scripts/dt_models.py /home/dt_api/
COPY APIs/Data_Exporter_API/Scripts/dt_opensearch_client.py /home/dt_api/
COPY APIs/Data_Exporter_API/Scripts/dt_service.py /home/dt_api/
COPY APIs/Data_Exporter_API/Scripts/dt_api_server.py /home/dt_api/
COPY APIs/Data_Exporter_API/Docker/Entrypoint/entrypoint_dt_api.py /home/dt_api/

RUN useradd -m -u 1000 dtapi && \
    chown -R dtapi:dtapi /home/dt_api && \
    chmod +x /home/dt_api/entrypoint_dt_api.py

USER dtapi

EXPOSE 8003

ENTRYPOINT ["python3", "/home/dt_api/entrypoint_dt_api.py"]
