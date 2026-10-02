FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir docker

COPY Intrusion_Detector_Module/Docker/Entrypoints/entrypoint_infra_discovery_watcher.py /app/entrypoint_infra_discovery_watcher.py

CMD ["python3", "/app/entrypoint_infra_discovery_watcher.py"]
