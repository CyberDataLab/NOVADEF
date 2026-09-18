<h1 align="center">PMP (Programmable Monitoring Platform)</h1>

PMP is an open source, modularly designed, programmable platform for collecting, exposing and visualising data from data sources in the Continuum Cloud. In addition, it provides threat detection to alert and notify on anomalous behaviour by analysing network traffic. Finally, PMP uses agnostic Sigma rules to configure the tools.

![Framework](https://github.com/CyberDataLab/ROBUST-6G_PMP/blob/main/PMP_design.svg)


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
- Fluentd
- Telegraf
- Falco
- Tshark
- Filebeat
- Kafka
- Snort3
- CICFlowMeter
- MongoDB
- PostgreSQL
- Prometheus
- Logstash
- OpenSearch
- ThingsBoard alarm collector
- Redis
- Grafana Mimir

:construction: Future development
- Grafana
- Sigma translator

## ⚙️ Installation

1. **Clone** the repository:
   ```bash
   gh repo clone CyberDataLab/ROBUST-6G_PMP
   ```
2. **Navigate** to the project directory:
   ```bash
   cd ROBUST-6G_PMP/
   ```

## 📋 Requirements

- `Docker` 28.5.1 or higher
- `Docker Compose` v2
- `Python` 3.12.x
- `Node.js` 20.20.2
- `pnpm` 10.33.3
- `uvicorn` 0.27.0
- `python3.12 -m pip install -r APIs/ConfigurationManager/requirements.txt`

Do not use the individual module compose files directly. PMP relies on generated environment files and launcher-managed profiles.

## 🕹️ Usage

1. **Bootstrap the current GUI/backend workflow**. This is the recommended entry point for the platform today.
   ```bash
   python3 Launcher/bootstrap_gui_backend.py
   ```
   This command starts the base stack, launches or reuses the Configuration Manager API on port `8000`, prepares the dashboard GUI, and starts or reuses the GUI on port `3000`.

2. **Understand the base stack started by the bootstrap**. By default it launches:
   - `kafka`
   - `filebeat`
   - `mongodb`
   - `mongodb_cm`
   - `postgres_gui`
   - `redis`
   - `mimir`
   - `prometheus`

3. **Run only part of the bootstrap flow when needed**.
   ```bash
   python3 Launcher/bootstrap_gui_backend.py --skip-gui
   python3 Launcher/bootstrap_gui_backend.py --skip-api --skip-gui
   python3 Launcher/bootstrap_gui_backend.py --gui-init-mode start-only
   python3 Launcher/bootstrap_gui_backend.py --gui-init-mode reinit
   ```

4. **Deploy monitoring tools through the Configuration Manager API** once the base stack is ready. The current public deploy endpoints expose:
   - `DeployNetworkTool`: `tshark`, `flow_module`
   - `DeployInfrastructureTool`: `telegraf`
   - `DeployServiceTool`: `fluentd`, `falco`
   - `DeploySecurityTool`: `snort3`

   Example:
   ```bash
   curl -X POST "http://localhost:8000/ConfigurationManager/DeployNetworkTool?toolName=tshark" \
     -H "Content-Type: application/json" \
     -d '{"configuration":{"TSHARK_INTERFACE":"eth0"}}'
   ```

   You can inspect configurable variables for a tool with:
   ```bash
   curl "http://localhost:8000/ConfigurationManager/getConfigurationOptions?toolName=tshark"
   ```

5. **Use the GUI for graphical launch and configuration**.
   - Open `http://localhost:3000`
   - The dashboard talks to the same Configuration Manager API started by the bootstrap
   - The current GUI is wired to deploy `tshark` and `snort3`

6. **Use the manual launcher for modules not covered by the current API/GUI flow**. This is still useful for advanced or legacy workflows such as `aggregation_module`, `thingsboard_module`, or direct profile-based launches.
   ```bash
   python3 ./Launcher/start_containers.py all
   ```
   Or a targeted modular deployment:
   ```bash
   python3 ./Launcher/start_containers.py -m moduleName -t all
   python3 ./Launcher/start_containers.py -m moduleName -t toolName1,toolName2
   ```
   Example:
   ```bash
   python3 ./Launcher/start_containers.py \
     -m communication_module -t kafka,filebeat \
     -m db_module -t mongodb,mongodb_cm,postgres_gui \
     -m thingsboard_module -t alarm_collector
   ```

7. **Stop the GUI/backend workflow**.
   ```bash
   python3 Launcher/stop_gui_backend.py
   ```
   By default this stops:
   - the dashboard GUI process
   - the Configuration Manager API process
   - the tool containers launched dynamically through the API

8. **Stop additional resources when required**.
   ```bash
   python3 Launcher/stop_gui_backend.py --stop-base
   python3 Launcher/stop_gui_backend.py --stop-all
   python3 Launcher/stop_gui_backend.py --purge
   ```

## :notebook: Notes

Table of current modules and launcher profiles implemented.

| Module | Tools / profiles |
|:--|:--|
| `alert_module` | `alert_module` |
| `communication_module` | `kafka`, `filebeat` |
| `collection_module` | `fluentd`, `telegraf`, `tshark`, `falco`, `info` |
| `flow_module` | `flow_module` |
| `db_module` | `mongodb`, `mongodb_cm`, `postgres_gui`, `redis` , `mimir` |
| `aggregation_module` | `prometheus`, `opensearch` |
| `thingsboard_module` | `alarm_collector` |
| `apis_module` | `nrtdr_api`, `hdr_api`, `dt_api` |

Additional implementation notes:

- In the current API workflow, the alerting tool is requested as `snort3`, although the underlying launcher profile belongs to `alert_module`.
- The default bootstrap base stack is `communication_module.kafka,filebeat`, `db_module.mongodb,mongodb_cm,postgres_gui,redis,mimir` plus `aggregation_module.prometheus`.
- `info` exposes the endpoint addresses of the deployed collection tools together with the host `machine_id`. Use it when `prometheus` is required.
- Runtime logs generated by the GUI/backend bootstrap flow are stored in `Internal_logs/`.

There are more containers associated with some tools to provide necessary services such as these:

- _Collection_Module > falco-exporter_: `falco` deploys `falco_exporter_novadef` automatically so metrics can be exposed to `prometheus`.
- _Databases_module > redis-worker_: `redis` deploys `redis_worker_novadef` automatically to stream Kafka data into Redis.
- _Aggregation_module > init-prometheus_: Changes the owner of the `/prometheus` folder to user `65534` (`nobody`) before `prometheus` starts.
- _Aggregation_module > init-prometheus-config_: Prepares the Prometheus configuration volume before the main server starts.
- _Aggregation_module > discovery-agent_: Continuously scans the network to discover devices exposing `info` endpoints for `prometheus`.
- _Aggregation_module > init-opensearch_: Fixes OpenSearch data permissions before `opensearch` starts.
- _Aggregation_module > opensearch-dashboards_: Official dashboard implementation for `opensearch`.
- _Aggregation_module > logstash_: Normalises Kafka topics into Elastic Common Schema and forwards them to `opensearch`.

## :heavy_exclamation_mark: Errors

If you are using PMP locally, update the `/etc/hosts` file to avoid issues with DNS addressing on Kafka and Grafana Mimir brokers. For example:

```bash
sudo nano /etc/hosts
```

Write the following line below the `127.0.1.1 user` entry:

```bash
yourIP kafka_novadef-node1.lan
yourIP mimir_novadef-node1.lan
```

If `bootstrap_gui_backend.py` reports that port `3000` or `8000` is already in use, free the port first or launch the services on different ports with `--gui-port` and `--api-port`.

If the GUI bootstrap fails because `pnpm` or `uvicorn` is missing, install the missing dependency and rerun the bootstrap command.

## 📜 License

PMP is **open-source** and distributed under the GNU AGPLv3 License. See `LICENSE` for more information.

- **Community Edition** — released under the **GNU Affero GPL v3.0**
- **Enterprise Edition** — proprietary license and premium support available

Contact **alberto.garciap@um.es** and **josemaria.jorquera@um.es** for commercial terms.
