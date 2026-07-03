FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        nmap \
        hping3 \
        curl \
        iputils-ping \
        iproute2 \
        openssh-client \
        sshpass \
        python3 \
        python3-pip \
    && pip3 install --no-cache-dir --break-system-packages confluent-kafka==2.3.0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

CMD ["/bin/sh", "-c", "tail -f /dev/null"]
