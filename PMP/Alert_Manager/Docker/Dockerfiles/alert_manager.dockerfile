FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir confluent-kafka==2.6.1

COPY Alert_Manager/Docker/Entrypoints/alert_manager.py /app/alert_manager.py

ENTRYPOINT ["python", "-u", "/app/alert_manager.py"]
