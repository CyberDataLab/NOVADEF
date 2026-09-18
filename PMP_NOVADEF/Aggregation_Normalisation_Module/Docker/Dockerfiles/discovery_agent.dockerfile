#sudo docker build -f .Aggregation_Normalisation_Module/Docker/Dockerfiles/discovery_agent.dockerfile -t discovery_agent_novadef:latest .

FROM alpine:3.23.0

RUN apk add --update --no-cache python3
RUN apk add py3-pip
RUN apk add nmap


ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN pip install flask netaddr requests

COPY Aggregation_Normalisation_Module/Docker/Entrypoints/entrypoint_discovery_agent.py /opt/discovery/entrypoint_discovery_agent.py

WORKDIR /opt/discovery

ENTRYPOINT ["python3", "/opt/discovery/entrypoint_discovery_agent.py"]
