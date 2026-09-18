FROM python:3.12-slim

WORKDIR /home/init_mongo_users

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN pip install --no-cache-dir pymongo==4.10.1

COPY Databases_module/Docker/Entrypoints/entrypoint_init_mongo_users.py /home/init_mongo_users/

RUN useradd -m -u 1000 initmongo && \
    chown -R initmongo:initmongo /home/init_mongo_users

USER initmongo

ENTRYPOINT ["python3", "/home/init_mongo_users/entrypoint_init_mongo_users.py"]
