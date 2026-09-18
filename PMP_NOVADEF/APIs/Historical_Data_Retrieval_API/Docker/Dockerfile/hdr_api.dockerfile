FROM python:3.12-slim

WORKDIR /home/hdr_api

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

COPY APIs/Historical_Data_Retrieval_API/Scripts/hdr_config.py /home/hdr_api/
COPY APIs/Historical_Data_Retrieval_API/Scripts/hdr_catalog.py /home/hdr_api/
COPY APIs/Historical_Data_Retrieval_API/Scripts/hdr_models.py /home/hdr_api/
COPY APIs/Historical_Data_Retrieval_API/Scripts/hdr_mimir_client.py /home/hdr_api/
COPY APIs/Historical_Data_Retrieval_API/Scripts/hdr_service.py /home/hdr_api/
COPY APIs/Historical_Data_Retrieval_API/Scripts/hdr_api_server.py /home/hdr_api/
COPY APIs/Historical_Data_Retrieval_API/Docker/Entrypoint/entrypoint_hdr_api.py /home/hdr_api/

RUN useradd -m -u 1000 hdrapi && \
    chown -R hdrapi:hdrapi /home/hdr_api && \
    chmod +x /home/hdr_api/entrypoint_hdr_api.py

USER hdrapi

EXPOSE 8002

ENTRYPOINT ["python3", "/home/hdr_api/entrypoint_hdr_api.py"]
