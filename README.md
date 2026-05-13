# NOVADEF

NOVADEF is a platform for monitoring, detection, attacker profiling, and incident response orchestration in cyber defense scenarios.

## Quick Start

From the repository root:

```bash
bash start_novadef_complete.sh
```

This is the official and only startup script in the root directory to bring up the full environment.

## GUI and Services

Once startup is complete, open the web hub:

- `http://localhost:18080`

From there, you can access the exposed services directly.

## Running Experiments

With NOVADEF up and running, launch the attack stimuli:

```bash
# Experiment 1 (network / password spraying)
python3 Experiments/run_scenario_integrated_experiments.py --only exp1

# Experiment 2 (host / emulated ransomware)
python3 Experiments/run_scenario_integrated_experiments.py --only exp2
```

The `Experiments` script only triggers emulated attacks inside the scenario.  
Detection, profiling, enrichment (MISP), countermeasure selection (MITRE D3FEND), orchestration (SOARCA), and final reporting are expected to run through NOVADEF's internal workflow.

## Main Structure

- `PMP/`: monitoring, alerting, and pipeline integrations.
- `TAPCD/`: attacker profiling and related intelligence.
- `MISP/`: threat intelligence deployment and integration.
- `SOARCA/`: response orchestration and execution.
- `Scenario/`: attacker/victim lab machines and scripts.
- `Experiments/`: attack stimulus launcher.
- `NOVADEF_GUI/`: web interface with quick service links.

## License

Distributed under GNU AGPLv3. See [LICENSE](LICENSE).

- **Community Edition**: **GNU Affero GPL v3.0**.
- **Enterprise Edition**: proprietary license and premium support.

Commercial contact: **alberto.garciap@um.es**, **pedro.beltranl@um.es**, **josemaria.jorquera@um.es**.
