FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc g++ \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir confluent-kafka numpy scikit-learn

COPY Alert_Module/Docker/Entrypoints/entrypoint_network_intrusion_detector.py /app/entrypoint_network_intrusion_detector.py

CMD ["python3", "/app/entrypoint_network_intrusion_detector.py"]
