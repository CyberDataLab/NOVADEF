#sudo docker build -f ./Data_Collection_Module/Docker/Dockerfiles/falco.dockerfile -t falco_novadef:latest .

FROM falcosecurity/falco:0.40.0

COPY Data_Collection_Module/Configuration_Files/Falco/falco.yaml /etc/Falco/falco.yaml
COPY Data_Collection_Module/Configuration_Files/Falco/. /etc/Falco
COPY Data_Collection_Module/Docker/Entrypoints/entrypoint_falco.sh /entrypoint_falco.sh

RUN chmod +x /entrypoint_falco.sh
RUN mkdir -p /falco/logs

ENTRYPOINT ["/entrypoint_falco.sh"]
