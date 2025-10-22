#!/usr/bin/env bash
if [ $# -eq 2 ]
then
    ENV_DIR=/home/Flow_Module/Preinstall/CICFlowMeter/cfm_env
    source "$ENV_DIR/bin/activate"
    SCAPY_BPF=0 cicflowmeter -f "$1" -c "$2"
    deactivate
else
    echo -e "Please introduce only 2 arguments.\\n\\t 1. PCAP input file \\n\\t 2. CSV output file"
fi