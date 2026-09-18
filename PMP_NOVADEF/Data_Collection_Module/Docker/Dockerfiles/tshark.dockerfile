#sudo docker build -f ./Data_Collection_Module/Docker/Dockerfiles/tshark.dockerfile -t tshark_novadef:latest .
FROM alpine:3.23.0

# Installing Tshark and required dependencies
RUN apk add --no-cache tshark libcap
RUN apk add --update --no-cache python3



# Set permissions so that Tshark can run without sudo
RUN setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap \
    && getcap /usr/bin/dumpcap \
    && chmod +x /usr/bin/dumpcap

# Trace storage
RUN mkdir -p /data/traces && chmod 777 /data/traces


# Entrypoint and auxiliary scripts
COPY Data_Collection_Module/Docker/Entrypoints/entrypoint_tshark.py /usr/local/bin/entrypoint_tshark.py
COPY Data_Collection_Module/Scripts/search_interface.py /usr/local/bin/search_interface.py
COPY Data_Collection_Module/Scripts/json_array_to_ndjson.py /usr/local/bin/json_array_to_ndjson.py

RUN chmod +x /usr/local/bin/search_interface.py /usr/local/bin/entrypoint_tshark.py /usr/local/bin/json_array_to_ndjson.py

ENTRYPOINT ["/usr/bin/python3", "/usr/local/bin/entrypoint_tshark.py"]
