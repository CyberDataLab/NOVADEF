<h1 align="center">PMP (Programmable Monitoring Platform)</h1>

PMP is an open source, modularly designed, programmable platform for collecting, exposing and visualising data from data sources in the Continuum Cloud. In addition, it provides threat detection to alert and notify on anomalous behaviour by analysing network traffic. Finally, PMP uses agnostic Sigma rules to configure the tools.

## 🔧 Features

 - :cyclone: **Data collection in real time**
 - :electric_plug: **Automation process**
 - :bell: **Alerts and notifications**
 - :hammer: **Dynamic configuration**
 - :bar_chart: **Data visualisation**
 - :heavy_plus_sign: **Modular**
 - 🚀 **RESTful Public API for programmatic access**
 - 🐳 **Dockerized deployment for easy setup**  

## :nut_and_bolt: Tools

:lock: Developed
 * Fluentd
 * Telegraf
 * Falco
 * Tshark
 * Filebeat
 * Kafka
 * Snort3
 * MongoDB
 * CICFlowMeter
 * Prometheus
 * Logstash
 * OpenSearch

:construction: Future development
 * Grafana
 * InfluxDB
 * Sigma translator

## ⚙️ Installation

1. **Clone** the repository:
   ```bash
   gh repo clone CyberDataLab/NOVADEF
   ```
2. **Navigate** to the project directory:
   ```bash
   cd NOVADEF/PMP
   ```

## 🕹️ Usage

1. **Usage and deployment** as a general option in which all modules are activated.
   ```bash
   python3 ./Launcher/start_containers.py all
   ```
2. **Usage and deployment** exploiting the modularity of PMP. Use `-m` to name each **module** followed by `-t` with the simple name of the **tools** to be deployed. Tools can be concatenated using **spaces** or **commas**. If you need to use **all the tools** in the module, you can use `-t all`.
   ```bash
   sudo python3 ./Launcher/start_containers.py -m moduleName -t all
   ```
    Or
   ```bash
   sudo python3 ./Launcher/start_containers.py -m moduleName -t toolName1,toolName2
   ```
    In example
   ```bash
   sudo python3 ./Launcher/start_containers.py -m alert_module -t all -m db_module -t all -m communication_module -t all -m flow_module -t all -m collection_module -t tshark,fluentd,telegraf
   ```

Do not use the `docker-compose.yml` file, as the PMP requires an environment file to run correctly.

3. **Deletes** containers, volumes, and Docker networks, but not the data generated.
   ```bash
   python3 ./Launcher/remove_containers.py
   ```

## :notebook: Notes
Table of current modules and tools implemented.

|        Modules       |    Tool 1    |  Tool 2   |  Tool 3 |  Tool 4 |  Tool 5 |
|:--------------------:|:------------:|:---------:|:-------:|:-------:|:-------:|
|     alert_module     | alert_module |           |         |         |         |
| communication_module |     kafka    | filebeat  |         |         |         |
|   collection_module  |    fluentd   | telegraf  |  tshark |  falco  |  info\* |
|      flow_module     |  flow_module |           |         |         |         |
|       db_module      |    mongodb   |           |         |         |         |
|  aggregation_module  |   prometheus |opensearch |         |         |         |

\* info: This container exposes the endpoint addresses of the data collection tools deployed on the target device, as well as its machine_id, which identifies it. Use it only if `prometheus` is to be deployed or is already deployed.

There are more containers associated with some tools to provide necessary services such as these:

 * _Collection_Module > falco-exporter_: `falco` has a current exporter plugin developed by the official organisation to expose information to `prometheus`. It is automatically implemented with `falco`.
 * _Aggregation_module > init-prometheus_: Used to change the owner of the /prometheus folder to user 65534 (nobody). It is necessary to manage `prometheus` data from the Docker volume. It changes the owner and is removed when its job is done. It is automatically deployed with `prometheus`.
 * _Aggregation_module > discovery-agent_: Continuously scans the network to discover devices that expose their data from the `info` container. `prometheus` extracts the information from the endpoint of this container. It is automatically deployed with `prometheus`.
 * _Aggregation_module > init-opensearch_: Performs the same task as the `init-prometheus` container, but is used in `opensearch` to correct OpenSearch data permissions (UID 1000). It is automatically implemented with `opensearch`.
 * _Aggregation_module > opensearch-dashboards_: Official dashboard implementation for `opensearch`. Used to visualise data exposed to `opensearch` in Elastic Common Schema format. Automatically deployed with `opensearch`.
 * _Aggregation_module > logstash_: This container implements `logstash` to analyse information from `kafka` topics to Elastic Common Schema. It sends the information to `opensearch`. It is automatically deployed with `opensearch`.

## 📋 Requirements

 * `Docker` 28.5.1 or higher.
 * ~~`docker-compose` 1.29.2 or higher.~~ Please do not use the individual docker-compose module. Docker 28.5.1 or higher utilises the updated version of `docker compose`, which has the appropriate functionalities to run the PMP.
 * `Python3.12` or higher.

The tool containers already satisfy their requirements without the need of any user installation.

## 📜 License

PMP is **open-source** under the **GPL-3.0 license**. See the `LICENSE` file for details.

## :heavy_exclamation_mark: Errors

In case `filebeat.yml` is showing errors, change the permissions manually with: 

   ```bash
   sudo chmod 644 /Communication_Bus/Configuration_Files/filebeat.yml
   sudo chown root:root /Communication_Bus/Configuration_Files/filebeat.yml
   ``` 

If you are using PMP as a test on your local machine, remember to update the `/etc/hosts` file to avoid issues with DNS addressing on Kafka brokers. In example:

   ```bash
   sudo nano /etc/hosts
   ```

Write the following line below the `127.0.1.1       user`:

   ```bash
   yourIP	kafka_novadef-node1.lan
   ```
