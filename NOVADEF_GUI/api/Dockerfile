FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends docker.io && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY api/app.py /app/app.py
COPY index.html experiments.html experiment_live.html login.html /gui/
COPY header-bg.jpg novadef-logo.png bg-login.jpg /gui/

ENV NOVADEF_GUI_DIR=/gui

EXPOSE 18082
CMD ["python", "/app/app.py"]
