#sudo docker build -f ./Data_Collection_Module/Docker/Dockerfiles/device_info.dockerfile -t device_info_novadef:latest .

FROM alpine:3.23.0

RUN apk add --update --no-cache python3
RUN apk add py3-pip

ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN pip install fastapi uvicorn

COPY Data_Collection_Module/Docker/Entrypoints/entrypoint_device_info.py /usr/local/bin/entrypoint_device_info.py

RUN chmod +x /usr/local/bin/entrypoint_device_info.py


ENTRYPOINT ["python3", "/usr/local/bin/entrypoint_device_info.py" ]
