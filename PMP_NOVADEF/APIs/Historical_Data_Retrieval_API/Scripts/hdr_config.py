#!/usr/bin/env python3
"""
Environment configuration for the Historical Data Retrieval API.

All default values live in a single place: HdrApiConfig in
Launcher/internal_external_tools_models.py. This module only reads the
environment variables that the compose file injects from that model, it does
not redeclare any default, to avoid two sources of truth drifting apart.
"""

from __future__ import annotations

import os


MIMIR_HOST: str = os.environ["MIMIR_HOST"]
MIMIR_PORT: str = os.environ["MIMIR_PORT"]
MIMIR_BASE_URL: str = f"http://{MIMIR_HOST}:{MIMIR_PORT}"
MIMIR_QUERY_PREFIX: str = "/prometheus/api/v1"

HDR_API_HOST: str = os.environ["HDR_API_HOST"]
HDR_API_PORT: int = int(os.environ["HDR_API_PORT"])

HDR_HTTP_TIMEOUT_SECONDS: float = float(os.environ["HDR_HTTP_TIMEOUT_SECONDS"])
HDR_MAX_RANGE_POINTS: int = int(os.environ["HDR_MAX_RANGE_POINTS"])
HDR_DEFAULT_STEP_SECONDS: int = int(os.environ["HDR_DEFAULT_STEP_SECONDS"])
