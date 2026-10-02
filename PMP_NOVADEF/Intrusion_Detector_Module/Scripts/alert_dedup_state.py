"""Persistence for emitted alerts and the alert-dedup TTL state.

Not campaign correlation (that's Alert_Manager's job) — this is only a
disk-backed record of "already alerted" targets, so a detector restart
mid-attack does not immediately re-alert.
"""

import json
import time
from pathlib import Path
from typing import Any

from Scripts.config import ALERT_DEDUP_TTL_SECONDS

RESULTS_DIR = Path("/app/results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
ALERTS_PATH = RESULTS_DIR / "network_intrusion_alerts.jsonl"
ALERT_DEDUP_STATE_PATH = RESULTS_DIR / "network_intrusion_alert_dedup_state.json"


def append_alert(alert: dict[str, Any]) -> None:
    """Append one emitted alert as a JSON line to the on-disk alert log."""
    with ALERTS_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(alert, ensure_ascii=False) + "\n")


def load_alert_dedup_state() -> dict[str, float]:
    """Load the persisted "last alerted at" timestamp per dedup key, dropping
    entries older than the dedup TTL."""
    if not ALERT_DEDUP_STATE_PATH.exists():
        return {}
    try:
        data = json.loads(ALERT_DEDUP_STATE_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            now = time.time()
            return {
                str(k): float(v)
                for k, v in data.items()
                if isinstance(v, (int, float)) and (now - float(v)) <= ALERT_DEDUP_TTL_SECONDS
            }
    except Exception:
        pass
    return {}


def save_alert_dedup_state(state: dict[str, float]) -> None:
    """Persist the "last alerted at" timestamp per dedup key, pruning expired entries."""
    try:
        now = time.time()
        pruned = {
            str(k): float(v)
            for k, v in state.items()
            if isinstance(v, (int, float)) and (now - float(v)) <= ALERT_DEDUP_TTL_SECONDS
        }
        ALERT_DEDUP_STATE_PATH.write_text(json.dumps(pruned, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass
