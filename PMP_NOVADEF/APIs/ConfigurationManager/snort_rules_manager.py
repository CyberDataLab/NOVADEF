"""
snort_rules_manager.py

Helper module for Snort3 custom rules lifecycle:
- parse and validate custom rules
- extract and validate SIDs
- detect collisions with snort3_community.rules
- apply add/remove/replace semantics
- manage temporary and definitive custom rules files
- validate candidate custom rules with an ephemeral Docker Compose service
"""

from __future__ import annotations

import os
import re
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


CUSTOM_SID_MIN = 1_000_001
RULE_SID_REGEX = re.compile(r"\bsid\s*:\s*(\d+)\s*;", re.IGNORECASE)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RULES_DIR = REPO_ROOT / "Alert_Module" / "Configuration_Files" / "Rules"
COMMUNITY_RULES_PATH = RULES_DIR / "snort3_community.rules"
CUSTOM_RULES_TMP_PATH = RULES_DIR / "snort3_custom.tmp.rules"
CUSTOM_RULES_FINAL_PATH = RULES_DIR / "snort3_custom.rules"
CONTAINER_RULES_DIR = Path("/home/Alert_Module/Snort_configuration/Rules")
CONTAINER_COMMUNITY_RULES_PATH = str(CONTAINER_RULES_DIR / "snort3_community.rules")
CONTAINER_CUSTOM_RULES_PATH = str(CONTAINER_RULES_DIR / "snort3_custom.rules")
SNORT_RULES_PATHS_SEPARATOR = ":"
ALERT_MODULE_COMPOSE_PATH = REPO_ROOT / "Alert_Module" / "Docker" / "alert_module_compose.yml"
VALIDATOR_SERVICE_NAME = "alert_rules_validator"
VALIDATOR_PROFILE = "alert_module.validator"
VALIDATOR_TIMEOUT_SECONDS = 300
VALIDATION_OUTPUT_LIMIT = 3000
VALIDATION_TAIL_LINE_COUNT = 40
VALIDATOR_COMPOSE_VARS = [
    "KAFKA_BOOTSTRAP",
    "SNORT_KAFKA_GROUP_ID",
    "SNORT_KAFKA_TOPIC_IN",
    "SNORT_KAFKA_TOPIC_OUT",
    "SNORT_RULES_PATHS",
    "SNORT_ALERT_TAP_IFACE",
    "MONGO_URI",
    "MONGO_INITDB_ROOT_USERNAME",
    "MONGO_INITDB_ROOT_PASSWORD",
    "MONGO_PORT",
    "SNORT_KAFKA_MESSAGE_FIELD",
    "SNORT_CONSUMER_KAFKA_AUTO_OFFSET_RESET",
    "SNORT_CONSUMER_KAFKA_ENABLE_AUTO_COMMIT",
    "SNORT_CONSUMER_KAFKA_PARTITION_ASSIGNMENT_STRATEGY",
    "SNORT_CONSUMER_KAFKA_ENABLE_PARTITION_EOF",
    "SNORT_CONSUMER_KAFKA_ALLOW_AUTO_CREATE_TOPICS",
    "SNORT_CONSUMER_FETCH_MIN_BYTES",
    "SNORT_CONSUMER_FETCH_WAIT_MAX_MS",
    "SNORT_CONSUMER_QUEUED_MAX_MESSAGES_KBYTES",
    "SNORT_CONSUMER_MAX_POLL_INTERVAL_MS",
    "SNORT_CONSUMER_SESSION_TIMEOUT_MS",
    "SNORT_PRODUCER_KAFKA_PRODUCER_LINGER_MS",
    "SNORT_PRODUCER_BATCH_NUM_MESSAGES",
    "SNORT_PRODUCER_KAFKA_PRODUCER_BATCH_SIZE",
    "SNORT_PRODUCER_KAFKA_PRODUCER_COMPRESSION",
]


def build_default_snort3_rules_config() -> Dict[str, Any]:
    """Return the default persisted rules_config structure for snort3."""
    return {
        "include_default_rules": True,
        "custom_rules": [],
        "custom_rule_sids": [],
    }


def build_snort3_rules_paths_env(rules_config: Optional[Dict[str, Any]]) -> str:
    """
    Build the internal SNORT_RULES_PATHS env value for the alert_module container.
    Fallback is always the community rules file if anything is missing or malformed.
    """
    if not rules_config:
        return CONTAINER_COMMUNITY_RULES_PATH

    custom_rules = [str(rule) for rule in rules_config.get("custom_rules", [])]
    include_default_rules = bool(rules_config.get("include_default_rules", True))

    if not custom_rules:
        return CONTAINER_COMMUNITY_RULES_PATH

    if include_default_rules:
        return SNORT_RULES_PATHS_SEPARATOR.join(
            [CONTAINER_COMMUNITY_RULES_PATH, CONTAINER_CUSTOM_RULES_PATH]
        )

    return CONTAINER_CUSTOM_RULES_PATH


def normalize_rule_strings(rules: List[str]) -> Tuple[bool, str, List[str]]:
    """Validate and normalize a list of rule strings."""
    if not isinstance(rules, list) or not rules:
        return False, "The 'rules' field must be a non-empty list of strings.", []

    normalized_rules: List[str] = []
    for rule in rules:
        if not isinstance(rule, str):
            return False, "Each rule in 'rules' must be a string.", []
        normalized_rule = rule.strip()
        if not normalized_rule:
            return False, "Rules cannot be empty strings.", []
        normalized_rules.append(normalized_rule)

    return True, "", normalized_rules


def normalize_rule_sids(rule_sids: List[str]) -> Tuple[bool, str, List[str]]:
    """Validate and normalize a list of rule SIDs received via the API."""
    if not isinstance(rule_sids, list) or not rule_sids:
        return False, "The 'rule_sids' field must be a non-empty list of strings.", []

    normalized_sids: List[str] = []
    seen: set[str] = set()
    for rule_sid in rule_sids:
        if not isinstance(rule_sid, str):
            return False, "Each item in 'rule_sids' must be a string.", []
        normalized_sid = rule_sid.strip()
        if not normalized_sid:
            return False, "Rule SIDs cannot be empty strings.", []
        if normalized_sid in seen:
            return False, f"Duplicate rule SID '{normalized_sid}' was provided.", []
        seen.add(normalized_sid)
        normalized_sids.append(normalized_sid)

    return True, "", normalized_sids


def extract_rule_sid(rule: str) -> Optional[str]:
    """Extract the SID value from a Snort3 rule string."""
    match = RULE_SID_REGEX.search(rule)
    if match is None:
        return None
    return match.group(1)


@lru_cache(maxsize=1)
def load_community_rule_sids() -> frozenset[str]:
    """
    Read snort3_community.rules and return the set of reserved SIDs.
    Cached because the community file is large and static during normal execution.
    """
    if not COMMUNITY_RULES_PATH.exists():
        raise FileNotFoundError(f"Snort3 community rules file not found at {COMMUNITY_RULES_PATH}")

    reserved_sids: set[str] = set()
    with COMMUNITY_RULES_PATH.open("r", encoding="utf-8", errors="replace") as rules_file:
        for line in rules_file:
            sid = extract_rule_sid(line)
            if sid is not None:
                reserved_sids.add(sid)

    return frozenset(reserved_sids)


def validate_custom_rule_sid(sid: str) -> Tuple[bool, str]:
    """Validate one custom SID against policy and community rules."""
    try:
        numeric_sid = int(sid)
    except ValueError:
        return False, f"Custom rule SID '{sid}' is not a valid integer value."

    if numeric_sid < CUSTOM_SID_MIN:
        return False, f"Custom rule SID {sid} is not allowed. Custom SIDs must be >= {CUSTOM_SID_MIN}."

    if sid in load_community_rule_sids():
        return False, f"Custom rule SID '{sid}' collides with a SID already present in snort3_community.rules."

    return True, ""


def build_custom_rule_sids(rules: List[str]) -> Tuple[bool, str, List[str]]:
    """Build the SID list for a set of custom rules, enforcing presence, uniqueness and policy."""
    custom_rule_sids: List[str] = []
    seen: set[str] = set()

    for rule in rules:
        sid = extract_rule_sid(rule)
        if sid is None:
            return False, "Each custom Snort3 rule must include a 'sid' value.", []
        if sid in seen:
            return False, f"Duplicate custom rule SID '{sid}' was provided.", []

        is_valid_sid, error_msg = validate_custom_rule_sid(sid)
        if not is_valid_sid:
            return False, error_msg, []

        seen.add(sid)
        custom_rule_sids.append(sid)

    return True, "", custom_rule_sids


def build_snort3_rules_config_for_deploy(
    rules: Optional[List[str]],
    include_default_rules: Optional[bool]
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Build the initial persisted rules_config for a snort3 deployment.
    Performs contract and business validation for custom rules.
    """
    if rules is None:
        if include_default_rules is False:
            return False, "Cannot set include_default_rules to false when no custom rules were provided.", {}
        return True, "", build_default_snort3_rules_config()

    is_valid_rules, error_msg, normalized_rules = normalize_rule_strings(rules)
    if not is_valid_rules:
        return False, error_msg, {}

    is_valid_sids, error_msg, custom_rule_sids = build_custom_rule_sids(normalized_rules)
    if not is_valid_sids:
        return False, error_msg, {}

    return True, "", {
        "include_default_rules": bool(include_default_rules) if include_default_rules is not None else False,
        "custom_rules": normalized_rules,
        "custom_rule_sids": custom_rule_sids,
    }


def apply_snort3_rules_update(
    existing_rules_config: Dict[str, Any],
    rules_action: str,
    rules: Optional[List[str]],
    rule_sids: Optional[List[str]],
    include_default_rules: Optional[bool]
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Apply rules_action semantics to the persisted snort3 rules_config.
    Includes business validation for custom rules, SID policy and community collisions.
    """
    current_rules_config = {
        "include_default_rules": bool(existing_rules_config.get("include_default_rules", True)),
        "custom_rules": [str(rule) for rule in existing_rules_config.get("custom_rules", [])],
        "custom_rule_sids": [str(sid) for sid in existing_rules_config.get("custom_rule_sids", [])],
    }

    if rules_action == "add":
        if include_default_rules is not None:
            return False, "The 'include_default_rules' field can only be changed through 'replace' for snort3.", {}
        if rules is None:
            return False, "The 'add' rules_action requires the 'rules' field.", {}
        if rule_sids is not None:
            return False, "The 'rule_sids' field is not valid together with rules_action 'add'.", {}

        is_valid_rules, error_msg, normalized_rules = normalize_rule_strings(rules)
        if not is_valid_rules:
            return False, error_msg, {}

        is_valid_sids, error_msg, new_rule_sids = build_custom_rule_sids(normalized_rules)
        if not is_valid_sids:
            return False, error_msg, {}

        existing_sids = set(current_rules_config["custom_rule_sids"])
        duplicated_sids = [sid for sid in new_rule_sids if sid in existing_sids]
        if duplicated_sids:
            return False, f"Custom rule SID '{duplicated_sids[0]}' is already present in the current snort3 configuration.", {}

        current_rules_config["custom_rules"].extend(normalized_rules)
        current_rules_config["custom_rule_sids"].extend(new_rule_sids)
        return True, "", current_rules_config

    if rules_action == "remove":
        if include_default_rules is not None:
            return False, "The 'include_default_rules' field is not allowed with rules_action 'remove'.", {}
        if rule_sids is None:
            return False, "The 'remove' rules_action requires the 'rule_sids' field.", {}
        if rules is not None:
            return False, "The 'rules' field is not valid together with rules_action 'remove'.", {}

        is_valid_sids, error_msg, normalized_rule_sids = normalize_rule_sids(rule_sids)
        if not is_valid_sids:
            return False, error_msg, {}

        existing_sids = set(current_rules_config["custom_rule_sids"])
        missing_sids = [sid for sid in normalized_rule_sids if sid not in existing_sids]
        if missing_sids:
            return False, f"Custom rule SID '{missing_sids[0]}' is not present in the current snort3 configuration.", {}

        remove_set = set(normalized_rule_sids)
        filtered_rules: List[str] = []
        filtered_sids: List[str] = []

        for rule in current_rules_config["custom_rules"]:
            sid = extract_rule_sid(rule)
            if sid is None:
                continue
            if sid not in remove_set:
                filtered_rules.append(rule)
                filtered_sids.append(sid)

        current_rules_config["custom_rules"] = filtered_rules
        current_rules_config["custom_rule_sids"] = filtered_sids
        return True, "", current_rules_config

    if rules_action == "replace":
        if rules is None:
            return False, "The 'replace' rules_action requires the 'rules' field.", {}
        if rule_sids is not None:
            return False, "The 'rule_sids' field is not valid together with rules_action 'replace'.", {}

        is_valid_rules, error_msg, normalized_rules = normalize_rule_strings(rules)
        if not is_valid_rules:
            return False, error_msg, {}

        is_valid_sids, error_msg, replacement_rule_sids = build_custom_rule_sids(normalized_rules)
        if not is_valid_sids:
            return False, error_msg, {}

        current_rules_config["include_default_rules"] = (
            bool(include_default_rules)
            if include_default_rules is not None
            else current_rules_config["include_default_rules"]
        )
        current_rules_config["custom_rules"] = normalized_rules
        current_rules_config["custom_rule_sids"] = replacement_rule_sids
        return True, "", current_rules_config

    return False, f"Unsupported rules_action '{rules_action}'.", {}


def write_rules_file(path: Path, rules: List[str]) -> None:
    """Write the provided rules to disk, one per line, ensuring a trailing newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    content = ""
    if rules:
        content = "\n".join(rules) + "\n"
    path.write_text(content, encoding="utf-8")


def remove_file_if_exists(path: Path) -> None:
    """Delete a file if it exists."""
    try:
        path.unlink()
    except FileNotFoundError:
        return


def capture_snort3_final_rules_state() -> Tuple[bool, Optional[str]]:
    """Capture whether the definitive custom rules file exists and, if so, its current content."""
    if not CUSTOM_RULES_FINAL_PATH.exists():
        return False, None
    return True, CUSTOM_RULES_FINAL_PATH.read_text(encoding="utf-8")


def restore_snort3_final_rules_state(previous_exists: bool, previous_content: Optional[str]) -> Tuple[bool, str]:
    """Restore the definitive custom rules file to the state captured before a failed operation."""
    try:
        cleanup_snort3_rules_tmp_file()
        if previous_exists:
            CUSTOM_RULES_FINAL_PATH.parent.mkdir(parents=True, exist_ok=True)
            CUSTOM_RULES_FINAL_PATH.write_text("" if previous_content is None else previous_content, encoding="utf-8")
        else:
            remove_file_if_exists(CUSTOM_RULES_FINAL_PATH)
        return True, ""
    except Exception as e:
        return False, f"Could not restore the previous Snort3 custom rules file state: {e}"


def cleanup_snort3_rules_tmp_file() -> None:
    """Delete the temporary custom rules file if it exists."""
    remove_file_if_exists(CUSTOM_RULES_TMP_PATH)


def cleanup_snort3_rules_files() -> None:
    """Delete both temporary and definitive custom rules files if they exist."""
    remove_file_if_exists(CUSTOM_RULES_TMP_PATH)
    remove_file_if_exists(CUSTOM_RULES_FINAL_PATH)


def write_snort3_rules_tmp_file(rules_config: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Write the candidate custom rules to the temporary file used by the validator.
    """
    custom_rules = [str(rule) for rule in rules_config.get("custom_rules", [])]

    try:
        write_rules_file(CUSTOM_RULES_TMP_PATH, custom_rules)
        return True, ""
    except Exception as e:
        return False, f"Could not write the temporary Snort3 custom rules file: {e}"


def sync_snort3_final_rules_file(rules_config: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Update the definitive custom rules file without validation.
    Used when a ruleset has already been validated previously and is only being reduced via remove,
    or when no custom rules should remain on disk.
    """
    custom_rules = [str(rule) for rule in rules_config.get("custom_rules", [])]

    try:
        cleanup_snort3_rules_tmp_file()
        if not custom_rules:
            remove_file_if_exists(CUSTOM_RULES_FINAL_PATH)
            return True, ""

        write_rules_file(CUSTOM_RULES_FINAL_PATH, custom_rules)
        return True, ""
    except Exception as e:
        return False, f"Could not update the definitive Snort3 custom rules file: {e}"


def promote_snort3_tmp_to_final() -> Tuple[bool, str]:
    """Promote the validated temporary custom rules file to the definitive location."""
    try:
        if not CUSTOM_RULES_TMP_PATH.exists():
            return False, "Temporary Snort3 custom rules file was not found after validation."
        CUSTOM_RULES_TMP_PATH.replace(CUSTOM_RULES_FINAL_PATH)
        return True, ""
    except Exception as e:
        return False, f"Could not promote the validated Snort3 rules file: {e}"


def _build_validator_env() -> Dict[str, str]:
    """Build the environment used for Docker Compose interpolation during validation."""
    env = os.environ.copy()
    env["PFD"] = str(REPO_ROOT)
    env.setdefault("TZ", "UTC")
    env.setdefault("MONGO_PORT", "27017")
    for var_name in VALIDATOR_COMPOSE_VARS:
        env.setdefault(var_name, "")
    return env


def _truncate_validation_output(text: str) -> str:
    """Trim validator stdout/stderr so API errors stay readable."""
    normalized = text.strip()
    if len(normalized) <= VALIDATION_OUTPUT_LIMIT:
        return normalized
    return normalized[:VALIDATION_OUTPUT_LIMIT].rstrip() + "\n...[truncated]"


def _extract_relevant_validation_output(text: str) -> str:
    """
    Prefer the Snort-specific validation section over Docker build noise.
    Falls back to the last lines if no Snort marker is found.
    """
    normalized = text.strip()
    if not normalized:
        return ""

    error_markers = ["ERROR:", "FATAL:"]
    error_positions = [normalized.rfind(marker) for marker in error_markers]
    error_positions = [position for position in error_positions if position != -1]
    if error_positions:
        return normalized[min(error_positions):]

    markers = [
        'o")~   Snort++',
        "Loading /home/Alert_Module/Snort_configuration/lua/snort.lua:",
        "Loading /home/Alert_Module/Snort_configuration/Rules/snort3_custom.tmp.rules:",
    ]

    marker_positions = [normalized.rfind(marker) for marker in markers]
    marker_positions = [position for position in marker_positions if position != -1]
    if marker_positions:
        return normalized[min(marker_positions):]

    lines = normalized.splitlines()
    return "\n".join(lines[-VALIDATION_TAIL_LINE_COUNT:])


def run_snort_rules_validator() -> Tuple[bool, str]:
    """
    Validate the temporary custom rules file with an ephemeral Docker Compose service
    that reuses the alert_module image but runs `snort -T` instead of the normal entrypoint.
    """
    cmd = [
        "docker",
        "compose",
        "--profile",
        VALIDATOR_PROFILE,
        "-f",
        str(ALERT_MODULE_COMPOSE_PATH),
        "run",
        "--rm",
        "--no-deps",
        VALIDATOR_SERVICE_NAME,
    ]

    try:
        completed = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            env=_build_validator_env(),
            capture_output=True,
            text=True,
            timeout=VALIDATOR_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        cleanup_snort3_rules_tmp_file()
        return False, "Snort3 rule validation timed out."
    except FileNotFoundError as e:
        cleanup_snort3_rules_tmp_file()
        return False, f"Could not execute Docker Compose for Snort3 validation: {e}"
    except Exception as e:
        cleanup_snort3_rules_tmp_file()
        return False, f"Unexpected error while validating Snort3 rules: {e}"

    if completed.returncode == 0:
        return True, ""

    cleanup_snort3_rules_tmp_file()
    combined_output = "\n".join(
        part for part in [completed.stdout, completed.stderr] if part and part.strip()
    )
    details = _truncate_validation_output(_extract_relevant_validation_output(combined_output))
    if details:
        return False, f"Snort3 rule validation failed.\n{details}"
    return False, "Snort3 rule validation failed."


def apply_snort3_rules_files(rules_config: Dict[str, Any], validate_custom_rules: bool) -> Tuple[bool, str]:
    """
    Apply the required file lifecycle for the current snort3 rules candidate.

    - If there are no custom rules, delete temporary and definitive files.
    - If validation is required, write the temporary file, run the validator,
      and promote it to the definitive file only when validation succeeds.
    - If validation is not required, update the definitive file directly.
    """
    custom_rules = [str(rule) for rule in rules_config.get("custom_rules", [])]

    if not custom_rules:
        try:
            cleanup_snort3_rules_files()
            return True, ""
        except Exception as e:
            return False, f"Could not clean Snort3 custom rules files: {e}"

    if not validate_custom_rules:
        return sync_snort3_final_rules_file(rules_config)

    is_written, write_error = write_snort3_rules_tmp_file(rules_config)
    if not is_written:
        cleanup_snort3_rules_tmp_file()
        return False, write_error

    is_valid, validation_error = run_snort_rules_validator()
    if not is_valid:
        return False, validation_error

    return promote_snort3_tmp_to_final()
