#sudo docker build -f ./Flow_Module/Docker/Dockerfiles/flow_module.dockerfile -t flow_module_novadef:latest .

FROM ubuntu:jammy

ENV DEBIAN_FRONTEND=noninteractive 
RUN apt update -y && apt upgrade -y

#JSON2PCAP and Kafka.io dependencies
RUN apt install python3-pip -y
RUN pip install ijson scapy bitstring confluent-kafka pymongo
RUN apt-get update && apt-get install -y --no-install-recommends \
  libpcap0.8 libpcap0.8-dev tcpdump && \
rm -rf /var/lib/apt/lists/*



#Crear todas las carpetas
RUN mkdir -p /home/Flow_Module \
    /home/Flow_Module/Results/Flows \
    /home/Flow_Module/Scripts/Parsing/PCAP_Files \
    /home/Flow_Module/Scripts/Parsing/JSON2PCAP \
    /home/Flow_Module/Preinstall/Updated_Python \
    /home/Flow_Module/Preinstall/CICFlowMeter

COPY ./Flow_Module/Scripts/JSON2PCAP/. /home/Flow_Module/Scripts/Parsing/JSON2PCAP
COPY ./Flow_Module/Scripts/install_python3.12.sh /home/Flow_Module/Preinstall/Updated_Python
COPY ./Flow_Module/Scripts/Automatic_cicflowmeter/. /home/Flow_Module/Preinstall/CICFlowMeter
COPY ./Flow_Module/Docker/Entrypoints/entrypoint_flow_module.py /home/Flow_Module
COPY ./Flow_Module/Scripts/kafka_io.py /home/Flow_Module/Scripts
#Instalar python3.12 con script
RUN chmod +x /home/Flow_Module/Preinstall/Updated_Python/install_python3.12.sh \
    && /home/Flow_Module/Preinstall/Updated_Python/install_python3.12.sh
#Instalar entorno para CICFlowMeter
RUN chmod +x /home/Flow_Module/Preinstall/CICFlowMeter/launch_cfm.sh \
    && python3.12 /home/Flow_Module/Preinstall/CICFlowMeter/install_cfm.py /home/Flow_Module/Preinstall/CICFlowMeter/cfm_env /usr/bin/python3.12

    #Lanzar entrypoint
ENTRYPOINT [ "/usr/bin/python3" , "/home/Flow_Module/entrypoint_flow_module.py" ]