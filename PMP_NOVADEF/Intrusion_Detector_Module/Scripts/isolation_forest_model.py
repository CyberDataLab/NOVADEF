"""Isolation Forest anomaly model for the slow-path (flow-statistics) detector."""

import logging
import time
from hashlib import md5
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("network_intrusion_detector")


def generate_benign_batches() -> list[list[dict[str, Any]]]:
    """Generate a synthetic benign baseline (few sources, no auth failures, low
    request rate) that the Isolation Forest learns as "normal" traffic, so a
    password-spraying attack (many IPs, many failures, high rate) stands out."""
    rng = np.random.default_rng(42)
    batches = []
    port_pool = [22, 80, 443, 8080, 8443, 9000, 3000, 9090]
    for _ in range(500):
        event_count = int(rng.integers(3, 14))
        start = float(time.time()) - float(rng.integers(10_000, 20_000))
        batch = []
        # Legitimate traffic comes from a few stable sources, not a swarm.
        src_pool = [f"172.18.0.{int(rng.integers(60, 155))}" for _ in range(int(rng.integers(1, 4)))]
        # Mix of legitimate cadences: mostly slow (monitoring), but also fast
        # health-check/scraping bursts (multi-IP, no failures) so the model
        # does not confuse concurrent benign activity with an attack — the
        # real discriminator is failed_attempts (always 0 here) and source
        # count, not raw speed.
        fast_burst = bool(rng.random() < 0.35)
        spacing = float(rng.uniform(0.3, 3.0)) if fast_burst else float(rng.uniform(5, 90))
        for idx in range(event_count):
            src_ip = src_pool[int(rng.integers(0, len(src_pool)))]
            dst_port = int(port_pool[int(rng.integers(0, len(port_pool)))])
            batch.append(
                {
                    "src_ip": src_ip,
                    "dst_ip": "172.18.0.30",
                    "dst_port": dst_port,
                    "protocol": "tcp",
                    "username": src_ip,
                    "auth_success": True,
                    "pkt_len": int(rng.integers(54, 900)),
                    "timestamp": start + (idx * spacing * float(rng.uniform(0.7, 1.3))),
                }
            )
        batches.append(batch)
    return batches


class SprayingAnomalyModel:
    """Isolation Forest wrapper that scores a window of events for password-spraying-like anomalies."""

    feature_names = [
        "unique_src_ips",
        "unique_target_users",
        "failed_attempts",
        "requests_per_minute",
        "time_distribution_stddev",
        "port_variation",
        "protocol_diversity",
        "geographic_spread",
    ]

    def __init__(self) -> None:
        """Build the scaler and Isolation Forest with a low contamination
        rate, since the synthetic baseline is clean by construction."""
        self.scaler = StandardScaler()
        self.model = IsolationForest(contamination=0.02, random_state=42, n_estimators=200)
        # Calibrated in train() against the benign baseline.
        self.decision_threshold = 0.0

    def _features(self, events: list[dict[str, Any]]) -> np.ndarray:
        """Turn a window of events into the fixed feature vector the model scores."""
        if not events:
            return np.zeros((1, len(self.feature_names)), dtype=np.float32)

        timestamps = sorted(float(event.get("timestamp", 0.0)) for event in events)
        unique_src_ips = sorted({str(event.get("src_ip", "")) for event in events if event.get("src_ip")})
        unique_users = sorted({str(event.get("username", "")) for event in events if event.get("username")})
        failed_attempts = sum(1 for event in events if not bool(event.get("auth_success", False)))
        protocols = {str(event.get("protocol", "")).lower() for event in events if event.get("protocol")}
        ports = {int(event.get("dst_port", 0)) for event in events if event.get("dst_port")}

        time_span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 1.0
        rpm = (len(events) / max(time_span, 1.0)) * 60.0
        intervals = [timestamps[idx + 1] - timestamps[idx] for idx in range(len(timestamps) - 1)]
        time_std = float(np.std(intervals)) if intervals else 0.0
        geo_values = [int(md5(src_ip.encode()).hexdigest(), 16) % 256 for src_ip in unique_src_ips]
        geo_spread = float(np.std(geo_values)) if geo_values else 0.0

        return np.array(
            [[
                float(len(unique_src_ips)),
                float(len(unique_users)),
                float(failed_attempts),
                float(rpm),
                float(time_std),
                float(len(ports)),
                float(len(protocols)),
                float(geo_spread),
            ]],
            dtype=np.float32,
        )

    def __post_train_threshold(self, benign_scores: np.ndarray) -> None:
        """Calibrate the anomaly threshold just below the benign baseline's own
        1st percentile score, robust to the contamination parameter."""
        p_low = float(np.percentile(benign_scores, 1.0))
        self.decision_threshold = p_low - 0.01

    def train(self) -> None:
        """Fit the scaler and Isolation Forest on the synthetic benign baseline."""
        benign = generate_benign_batches()
        matrix = np.vstack([self._features(batch) for batch in benign])
        self.scaler.fit(matrix)
        scaled = self.scaler.transform(matrix)
        self.model.fit(scaled)
        benign_scores = self.model.decision_function(scaled)
        self.__post_train_threshold(benign_scores)
        logger.info(
            "Isolation Forest trained on synthetic benign baseline (%s batches). "
            "Anomaly threshold=%.4f (benign: min=%.4f p1=%.4f median=%.4f)",
            len(benign),
            self.decision_threshold,
            float(benign_scores.min()),
            float(np.percentile(benign_scores, 1.0)),
            float(np.median(benign_scores)),
        )

    def score(self, events: list[dict[str, Any]]) -> tuple[bool, float, dict[str, float]]:
        """Score a window of events, returning whether it is anomalous, its
        decision score, and the underlying feature values."""
        features = self._features(events)
        scaled = self.scaler.transform(features)
        decision = float(self.model.decision_function(scaled)[0])
        details = dict(zip(self.feature_names, [float(value) for value in features[0].tolist()]))
        threshold = getattr(self, "decision_threshold", 0.0)
        is_anomaly = decision < threshold
        return is_anomaly, decision, details
