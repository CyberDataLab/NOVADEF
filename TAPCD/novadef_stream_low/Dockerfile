FROM python:3.11-slim

WORKDIR /app

# Dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Código
COPY . .

# Logs sin buffer
ENV PYTHONUNBUFFERED=1

# Ejecutable principal (args llegarán desde compose)

