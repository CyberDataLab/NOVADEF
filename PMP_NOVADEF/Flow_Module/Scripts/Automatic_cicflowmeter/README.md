# automatic_cicflowmeter

**Installation of CICFlowMeter in a Python environment and PCAP parsing to CSV files.**

---

## Versions

- **Python:** 3.12
- **CICFlowMeter:** 0.1.9
- **Scapy:** 2.5.0

---

## Modifications

- `~/ENVIRONMENT_NAME/lib/python3.XX/site-packages/cicflowmeter/features/packet_time.py`
- `~/ENVIRONMENT_NAME/lib/python3.XX/site-packages/cicflowmeter/utils.py`
- `~/ENVIRONMENT_NAME/lib/python3.XX/site-packages/cicflowmeter/flow_session.py`

**Note:**  
`python3.XX` refers to the version of the Python interpreter.  
Always use at least **Python 3.12**.  
This configuration **does not work with lower versions**.

`ENVIRONMENT_NAME` refers to the name of your environment when using the install command.

---

## Installation Steps

1. **Clone the repository:**

    ```bash
    gh repo clone LongJeffreySilver/automatic_cicflowmeter
    ```

2. **In case you need to change permissions:**

    ```bash
    sudo chmod +x install_cfm.py launch_cfm.sh
    ```

3. **Install the environment:**

    ```bash
    python3 install_cfm.py ENVIRONMENT_NAME /usr/bin/python3.XX
    ```

    **Example:**

    ```bash
    python3 install_cfm.py ~/cfm_env /usr/bin/python3.12
    ```

    You can also specify a different Python interpreter version:

    ```bash
    python3.12 install_cfm.py ~/cfm_env /usr/bin/python3.12
    ```

4. **Once the environment is installed successfully, you will see the following message:**

    Activating the environment
    ```bash
    source {ACTIVATE}
    ```

    Parsing PCAP → CSV
    ```bash
    SCAPY_BPF=0 cicflowmeter -f trace.pcap -c result.csv -v
    ```
    Leaving the environment
    ```bash
    deactivate
    ```
---

## Automation

You can manually use the environment with the above commands, but to automate the process of analyzing flows between traces, use the launch_cfm.sh script.

    ./launch_cfm.sh trace.pcap result.csv

This script executes the following command.

    SCAPY_BPF=0 cicflowmeter -f trace.pcap -c result.csv"


---

## Notes

Make sure to replace **{ACTIVATE}** with the path to the activation script for your environment.

Ensure that your PCAP file (trace.pcap) and the output CSV file (result.csv) are in the **correct paths** for the commands to work properly.