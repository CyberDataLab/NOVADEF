#!/usr/bin/env python3
"""
Environment configuration for the Data Exporter API.

All default values live in a single place: DtApiConfig in
Launcher/internal_external_tools_models.py. This module only reads the
environment variables that the compose file injects from that model, it does
not redeclare any default, to avoid two sources of truth drifting apart.
"""

from __future__ import annotations

import os


OPENSEARCH_HOST: str = os.environ["OPENSEARCH_HOST"]
OPENSEARCH_REST_API_PORT: str = os.environ["OPENSEARCH_REST_API_PORT"]
OPENSEARCH_BASE_URL: str = f"https://{OPENSEARCH_HOST}:{OPENSEARCH_REST_API_PORT}"
OPENSEARCH_PASSWORD: str = os.environ["OPENSEARCH_PASSWORD"]
OPENSEARCH_USERNAME: str = "admin"

# Logstash writes daily indices named "logs-<kafka_topic>-YYYY.MM.dd" (see
# Aggregation_Normalisation_Module/Configuration_Files/Logstash/pipeline.conf);
# this pattern covers all of them regardless of dataset/module.
OPENSEARCH_LOGS_INDEX_PATTERN: str = "logs-*"

DT_API_HOST: str = os.environ["DT_API_HOST"]
DT_API_PORT: int = int(os.environ["DT_API_PORT"])

DT_HTTP_TIMEOUT_SECONDS: float = float(os.environ["DT_HTTP_TIMEOUT_SECONDS"])
DT_MAX_RANGE_POINTS: int = int(os.environ["DT_MAX_RANGE_POINTS"])
DT_DEFAULT_STEP_SECONDS: int = int(os.environ["DT_DEFAULT_STEP_SECONDS"])
DT_MAX_PAGE_SIZE: int = int(os.environ["DT_MAX_PAGE_SIZE"])
