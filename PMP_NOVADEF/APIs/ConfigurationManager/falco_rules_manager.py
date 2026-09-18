"""
falco_rules_manager.py

Helper module for Falco custom rules lifecycle:
- parse and normalize custom YAML blocks
- extract rule names from top-level Falco items
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


FALCO_TOP_LEVEL_ITEM_REGEX = re.compile(r"^-\s*(rule|macro|list)\s*:\s*(.+?)\s*$")
FALCO_RULES_PATHS_SEPARATOR = ":"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RULES_DIR = REPO_ROOT / "Data_Collection_Module" / "Configuration_Files" / "Falco"
COMMUNITY_RULES_PATH = RULES_DIR / "falco_community_rules.yaml"
CUSTOM_RULES_TMP_PATH = RULES_DIR / "falco_custom.tmp_rules.yaml"
CUSTOM_RULES_FINAL_PATH = RULES_DIR / "falco_rules.yaml"
CONTAINER_RULES_DIR = Path("/etc/Falco")
CONTAINER_COMMUNITY_RULES_PATH = str(CONTAINER_RULES_DIR / "falco_community_rules.yaml")
CONTAINER_CUSTOM_TMP_RULES_PATH = str(CONTAINER_RULES_DIR / "falco_custom.tmp_rules.yaml")
CONTAINER_CUSTOM_RULES_PATH = str(CONTAINER_RULES_DIR / "falco_rules.yaml")
DATA_COLLECTION_COMPOSE_PATH = REPO_ROOT / "Data_Collection_Module" / "Docker" / "data_collection_module_compose.yml"
VALIDATOR_SERVICE_NAME = "falco_rules_validator"
VALIDATOR_PROFILE = "collection_module.validator"
VALIDATOR_TIMEOUT_SECONDS = 300
VALIDATION_OUTPUT_LIMIT = 3000
VALIDATION_TAIL_LINE_COUNT = 40
VALIDATOR_COMPOSE_VARS = [
    "MACHINE_ID",
    "FALCO_SKIP_DRIVER_LOADER",
    "FALCO_EXPORTER_PORT",
    "FALCO_RULES_PATHS",
    "FALCO_VALIDATE_PATHS",
]


def build_default_falco_rules_config() -> Dict[str, Any]:
    """Return the default persisted rules_config structure for falco."""
    return {
        "include_default_rules": True,
        "custom_rules": [],
        "custom_rule_names": [],
    }


def build_falco_rules_paths_env(
    rules_config: Optional[Dict[str, Any]],
    *,
    use_tmp_custom_rules: bool = False,
) -> str:
    """
    Build the internal FALCO_RULES_PATHS env value for the Falco container.
    Fallback is always the community rules file if anything is missing or malformed.
    """
    if not rules_config:
        return CONTAINER_COMMUNITY_RULES_PATH

    custom_rules = [str(rule) for rule in rules_config.get("custom_rules", [])]
    include_default_rules = bool(rules_config.get("include_default_rules", True))
    custom_rules_path = (
        CONTAINER_CUSTOM_TMP_RULES_PATH if use_tmp_custom_rules else CONTAINER_CUSTOM_RULES_PATH
    )

    if not custom_rules:
        return CONTAINER_COMMUNITY_RULES_PATH

    if include_default_rules:
        return FALCO_RULES_PATHS_SEPARATOR.join(
            [CONTAINER_COMMUNITY_RULES_PATH, custom_rules_path]
        )

    return custom_rules_path


def normalize_rule_names(rule_names: List[str]) -> Tuple[bool, str, List[str]]:
    """Validate and normalize a list of Falco rule names received via the API."""
    if not isinstance(rule_names, list) or not rule_names:
        return False, "The 'rule_names' field must be a non-empty list of strings.", []

    normalized_rule_names: List[str] = []
    seen: set[str] = set()
    for rule_name in rule_names:
        if not isinstance(rule_name, str):
            return False, "Each item in 'rule_names' must be a string.", []
        normalized_rule_name = rule_name.strip()
        if not normalized_rule_name:
            return False, "Rule names cannot be empty strings.", []
        if normalized_rule_name in seen:
            return False, f"Duplicate rule name '{normalized_rule_name}' was provided.", []
        seen.add(normalized_rule_name)
        normalized_rule_names.append(normalized_rule_name)

    return True, "", normalized_rule_names


def _strip_matching_quotes(value: str) -> str:
    """Strip matching single or double quotes around a string value."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1].strip()
    return value


def _extract_falco_item_metadata(block: str) -> Tuple[bool, str, Optional[str], Optional[str]]:
    """
    Extract the top-level Falco item kind and its name from one YAML block.
    Supported top-level items are rule, macro and list.
    """
    for raw_line in block.splitlines():
        stripped_line = raw_line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            continue

        match = FALCO_TOP_LEVEL_ITEM_REGEX.match(stripped_line)
        if match is None:
            return (
                False,
                "Each custom Falco YAML block must start with '- rule:', '- macro:' or '- list:'.",
                None,
                None,
            )

        item_kind = match.group(1)
        item_name = _strip_matching_quotes(match.group(2).strip())
        if not item_name:
            return False, f"Custom Falco {item_kind} entries must include a non-empty name.", None, None
        return True, "", item_kind, item_name

    return False, "Custom Falco YAML blocks cannot be empty.", None, None


def split_falco_yaml_blocks(
    raw_text: str,
    *,
    validate_item_kinds: bool = True,
) -> Tuple[bool, str, List[str]]:
    """
    Split a raw Falco YAML string into top-level YAML item blocks.
    A single input string may contain one or more '- rule:' / '- macro:' / '- list:' items.
    """
    if not isinstance(raw_text, str):
        return False, "Each rule in 'rules' must be a string.", []

    stripped_text = raw_text.strip()
    if not stripped_text:
        return False, "Rules cannot be empty strings.", []

    blocks: List[str] = []
    current_block: List[str] = []
    preamble_lines: List[str] = []
    has_started_block = False

    for line in stripped_text.splitlines():
        normalized_line = line.rstrip()
        is_top_level_item = normalized_line.startswith("- ")

        if is_top_level_item:
            if current_block:
                blocks.append("\n".join(current_block).strip())
            current_block = []
            if preamble_lines:
                current_block.extend(preamble_lines)
                preamble_lines = []
            current_block.append(normalized_line)
            has_started_block = True
            continue

        stripped_line = normalized_line.strip()
        if not has_started_block:
            if not stripped_line or stripped_line.startswith("#"):
                preamble_lines.append(normalized_line)
                continue
            return (
                False,
                "Custom Falco YAML must declare each top-level item with '- rule:', '- macro:' or '- list:'.",
                [],
            )

        current_block.append(normalized_line)

    if current_block:
        blocks.append("\n".join(current_block).strip())

    if not blocks:
        return False, "The 'rules' field must contain at least one Falco YAML item.", []

    if validate_item_kinds:
        for block in blocks:
            is_valid_block, error_msg, _, _ = _extract_falco_item_metadata(block)
            if not is_valid_block:
                return False, error_msg, []

    return True, "", blocks


def normalize_rule_strings(rules: List[str]) -> Tuple[bool, str, List[str]]:
    """Validate and normalize a list of Falco custom YAML strings into top-level blocks."""
    if not isinstance(rules, list) or not rules:
        return False, "The 'rules' field must be a non-empty list of strings.", []

    normalized_rules: List[str] = []
    for rule in rules:
        is_valid_blocks, error_msg, blocks = split_falco_yaml_blocks(rule)
        if not is_valid_blocks:
            return False, error_msg, []
        normalized_rules.extend(blocks)

    return True, "", normalized_rules


def build_custom_rule_names(rules: List[str]) -> Tuple[bool, str, List[str]]:
    """Build the list of Falco rule names present in a set of top-level YAML blocks."""
    custom_rule_names: List[str] = []
    seen_rule_names: set[str] = set()

    for rule in rules:
        is_valid_block, error_msg, item_kind, item_name = _extract_falco_item_metadata(rule)
        if not is_valid_block:
            return False, error_msg, []

        if item_kind != "rule":
            continue

        assert item_name is not None
        if item_name in seen_rule_names:
            return False, f"Duplicate custom Falco rule name '{item_name}' was provided.", []

        seen_rule_names.add(item_name)
        custom_rule_names.append(item_name)

    return True, "", custom_rule_names


@lru_cache(maxsize=1)
def load_community_rule_names() -> frozenset[str]:
    """
    Read falco_community_rules.yaml and return the set of reserved rule names.
    Cached because the community file is large and static during normal execution.
    """
    if not COMMUNITY_RULES_PATH.exists():
        raise FileNotFoundError(f"Falco community rules file not found at {COMMUNITY_RULES_PATH}")

    reserved_rule_names: set[str] = set()
    is_valid_blocks, error_msg, blocks = split_falco_yaml_blocks(
        COMMUNITY_RULES_PATH.read_text(encoding="utf-8", errors="replace"),
        validate_item_kinds=False,
    )
    if not is_valid_blocks:
        raise ValueError(f"Could not parse Falco community rules file: {error_msg}")

    for block in blocks:
        is_valid_block, _, item_kind, item_name = _extract_falco_item_metadata(block)
        if not is_valid_block or item_kind != "rule" or item_name is None:
            continue
        reserved_rule_names.add(item_name)

    return frozenset(reserved_rule_names)


def validate_rule_name_collisions_with_community(
    rule_names: List[str],
    include_default_rules: bool,
) -> Tuple[bool, str]:
    """Reject custom Falco rule names that collide with the community ruleset when it is enabled."""
    if not include_default_rules:
        return True, ""

    community_rule_names = load_community_rule_names()
    for rule_name in rule_names:
        if rule_name in community_rule_names:
            return (
                False,
                f"Custom Falco rule '{rule_name}' collides with a rule already present in falco_community_rules.yaml.",
            )

    return True, ""


def build_falco_rules_config_for_deploy(
    rules: Optional[List[str]],
    include_default_rules: Optional[bool],
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Build the initial persisted rules_config for a falco deployment.
    Performs contract and business validation for custom YAML blocks.
    """
    if rules is None:
        if include_default_rules is False:
            return False, "Cannot set include_default_rules to false when no custom rules were provided.", {}
        return True, "", build_default_falco_rules_config()

    is_valid_rules, error_msg, normalized_rules = normalize_rule_strings(rules)
    if not is_valid_rules:
        return False, error_msg, {}

    is_valid_rule_names, error_msg, custom_rule_names = build_custom_rule_names(normalized_rules)
    if not is_valid_rule_names:
        return False, error_msg, {}

    include_default = bool(include_default_rules) if include_default_rules is not None else False
    are_rule_names_compatible, error_msg = validate_rule_name_collisions_with_community(
        custom_rule_names,
        include_default,
    )
    if not are_rule_names_compatible:
        return False, error_msg, {}

    return True, "", {
        "include_default_rules": include_default,
        "custom_rules": normalized_rules,
        "custom_rule_names": custom_rule_names,
    }


def apply_falco_rules_update(
    existing_rules_config: Dict[str, Any],
    rules_action: str,
    rules: Optional[List[str]],
    rule_names: Optional[List[str]],
    include_default_rules: Optional[bool],
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Apply rules_action semantics to the persisted falco rules_config.
    Remove works only on top-level rule entries identified by rule name.
    """
    current_rules_config = {
        "include_default_rules": bool(existing_rules_config.get("include_default_rules", True)),
        "custom_rules": [str(rule) for rule in existing_rules_config.get("custom_rules", [])],
        "custom_rule_names": [str(rule_name) for rule_name in existing_rules_config.get("custom_rule_names", [])],
    }

    if rules_action == "add":
        if include_default_rules is not None:
            return False, "The 'include_default_rules' field can only be changed through 'replace' for falco.", {}
        if rules is None:
            return False, "The 'add' rules_action requires the 'rules' field.", {}
        if rule_names is not None:
            return False, "The 'rule_names' field is not valid together with rules_action 'add'.", {}

        is_valid_rules, error_msg, normalized_rules = normalize_rule_strings(rules)
        if not is_valid_rules:
            return False, error_msg, {}

        is_valid_rule_names, error_msg, new_rule_names = build_custom_rule_names(normalized_rules)
        if not is_valid_rule_names:
            return False, error_msg, {}

        are_rule_names_compatible, error_msg = validate_rule_name_collisions_with_community(
            new_rule_names,
            current_rules_config["include_default_rules"],
        )
        if not are_rule_names_compatible:
            return False, error_msg, {}

        existing_rule_names = set(current_rules_config["custom_rule_names"])
        duplicated_rule_names = [rule_name for rule_name in new_rule_names if rule_name in existing_rule_names]
        if duplicated_rule_names:
            return (
                False,
                f"Custom Falco rule '{duplicated_rule_names[0]}' is already present in the current falco configuration.",
                {},
            )

        current_rules_config["custom_rules"].extend(normalized_rules)
        current_rules_config["custom_rule_names"].extend(new_rule_names)
        return True, "", current_rules_config

    if rules_action == "remove":
        if include_default_rules is not None:
            return False, "The 'include_default_rules' field is not allowed with rules_action 'remove'.", {}
        if rule_names is None:
            return False, "The 'remove' rules_action requires the 'rule_names' field.", {}
        if rules is not None:
            return False, "The 'rules' field is not valid together with rules_action 'remove'.", {}

        is_valid_rule_names, error_msg, normalized_rule_names = normalize_rule_names(rule_names)
        if not is_valid_rule_names:
            return False, error_msg, {}

        existing_rule_names = set(current_rules_config["custom_rule_names"])
        missing_rule_names = [rule_name for rule_name in normalized_rule_names if rule_name not in existing_rule_names]
        if missing_rule_names:
            return (
                False,
                f"Custom Falco rule '{missing_rule_names[0]}' is not present in the current falco configuration.",
                {},
            )

        remove_set = set(normalized_rule_names)
        filtered_rules: List[str] = []

        for rule in current_rules_config["custom_rules"]:
            is_valid_block, _, item_kind, item_name = _extract_falco_item_metadata(rule)
            if not is_valid_block:
                filtered_rules.append(rule)
                continue

            if item_kind == "rule" and item_name in remove_set:
                continue
            filtered_rules.append(rule)

        is_valid_remaining_rule_names, error_msg, remaining_rule_names = build_custom_rule_names(filtered_rules)
        if not is_valid_remaining_rule_names:
            return False, error_msg, {}

        current_rules_config["custom_rules"] = filtered_rules
        current_rules_config["custom_rule_names"] = remaining_rule_names
        return True, "", current_rules_config

    if rules_action == "replace":
        if rules is None:
            return False, "The 'replace' rules_action requires the 'rules' field.", {}
        if rule_names is not None:
            return False, "The 'rule_names' field is not valid together with rules_action 'replace'.", {}

        is_valid_rules, error_msg, normalized_rules = normalize_rule_strings(rules)
        if not is_valid_rules:
            return False, error_msg, {}

        is_valid_rule_names, error_msg, replacement_rule_names = build_custom_rule_names(normalized_rules)
        if not is_valid_rule_names:
            return False, error_msg, {}

        replacement_include_default_rules = (
            bool(include_default_rules)
            if include_default_rules is not None
            else current_rules_config["include_default_rules"]
        )
        are_rule_names_compatible, error_msg = validate_rule_name_collisions_with_community(
            replacement_rule_names,
            replacement_include_default_rules,
        )
        if not are_rule_names_compatible:
            return False, error_msg, {}

        current_rules_config["include_default_rules"] = replacement_include_default_rules
        current_rules_config["custom_rules"] = normalized_rules
        current_rules_config["custom_rule_names"] = replacement_rule_names
        return True, "", current_rules_config

    return False, f"Unsupported rules_action '{rules_action}'.", {}


def write_rules_file(path: Path, rules: List[str]) -> None:
    """Write the provided Falco YAML blocks to disk, preserving block separation."""
    path.parent.mkdir(parents=True, exist_ok=True)
    content = ""
    if rules:
        content = "\n\n".join(rules) + "\n"
    path.write_text(content, encoding="utf-8")


def remove_file_if_exists(path: Path) -> None:
    """Delete a file if it exists."""
    try:
        path.unlink()
    except FileNotFoundError:
        return


def capture_falco_final_rules_state() -> Tuple[bool, Optional[str]]:
    """Capture whether the definitive custom rules file exists and, if so, its current content."""
    if not CUSTOM_RULES_FINAL_PATH.exists():
        return False, None
    return True, CUSTOM_RULES_FINAL_PATH.read_text(encoding="utf-8")


def restore_falco_final_rules_state(previous_exists: bool, previous_content: Optional[str]) -> Tuple[bool, str]:
    """Restore the definitive custom rules file to the state captured before a failed operation."""
    try:
        cleanup_falco_rules_tmp_file()
        if previous_exists:
            CUSTOM_RULES_FINAL_PATH.parent.mkdir(parents=True, exist_ok=True)
            CUSTOM_RULES_FINAL_PATH.write_text(
                "" if previous_content is None else previous_content,
                encoding="utf-8",
            )
        else:
            remove_file_if_exists(CUSTOM_RULES_FINAL_PATH)
        return True, ""
    except Exception as e:
        return False, f"Could not restore the previous Falco custom rules file state: {e}"


def cleanup_falco_rules_tmp_file() -> None:
    """Delete the temporary custom rules file if it exists."""
    remove_file_if_exists(CUSTOM_RULES_TMP_PATH)


def cleanup_falco_rules_files() -> None:
    """Delete both temporary and definitive custom rules files if they exist."""
    remove_file_if_exists(CUSTOM_RULES_TMP_PATH)
    remove_file_if_exists(CUSTOM_RULES_FINAL_PATH)


def write_falco_rules_tmp_file(rules_config: Dict[str, Any]) -> Tuple[bool, str]:
    """Write the candidate custom YAML blocks to the temporary file used by the validator."""
    custom_rules = [str(rule) for rule in rules_config.get("custom_rules", [])]

    try:
        write_rules_file(CUSTOM_RULES_TMP_PATH, custom_rules)
        return True, ""
    except Exception as e:
        return False, f"Could not write the temporary Falco custom rules file: {e}"


def sync_falco_final_rules_file(rules_config: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Update the definitive custom rules file without validation.
    Used when a ruleset has already been validated previously and is only being reduced via remove,
    or when no custom rules should remain on disk.
    """
    custom_rules = [str(rule) for rule in rules_config.get("custom_rules", [])]

    try:
        cleanup_falco_rules_tmp_file()
        if not custom_rules:
            remove_file_if_exists(CUSTOM_RULES_FINAL_PATH)
            return True, ""

        write_rules_file(CUSTOM_RULES_FINAL_PATH, custom_rules)
        return True, ""
    except Exception as e:
        return False, f"Could not update the definitive Falco custom rules file: {e}"


def promote_falco_tmp_to_final() -> Tuple[bool, str]:
    """Promote the validated temporary custom rules file to the definitive location."""
    try:
        if not CUSTOM_RULES_TMP_PATH.exists():
            return False, "Temporary Falco custom rules file was not found after validation."
        CUSTOM_RULES_TMP_PATH.replace(CUSTOM_RULES_FINAL_PATH)
        return True, ""
    except Exception as e:
        return False, f"Could not promote the validated Falco rules file: {e}"


def _build_validator_env(rules_config: Dict[str, Any]) -> Dict[str, str]:
    """Build the environment used for Docker Compose interpolation during validation."""
    env = os.environ.copy()
    env["PFD"] = str(REPO_ROOT)
    env.setdefault("TZ", "UTC")
    env.setdefault("MACHINE_ID", "validator")
    env.setdefault("FALCO_SKIP_DRIVER_LOADER", "1")
    env.setdefault("FALCO_EXPORTER_PORT", "9376")
    env["FALCO_RULES_PATHS"] = (
        CONTAINER_COMMUNITY_RULES_PATH
        if bool(rules_config.get("include_default_rules", True))
        else ""
    )
    env["FALCO_VALIDATE_PATHS"] = CONTAINER_CUSTOM_TMP_RULES_PATH
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
    Prefer the Falco validation section over Docker build noise.
    Falls back to the last lines if no Falco marker is found.
    """
    normalized = text.strip()
    if not normalized:
        return ""
    lines = [line.strip() for line in normalized.splitlines() if line.strip()]
    if not lines:
        return ""

    filtered_lines = [
        line
        for line in lines
        if not line.startswith("#")
        and "transferring context:" not in line
        and "exporting layers" not in line
        and "resolving provenance" not in line
        and not line.startswith("Image ")
        and not line.startswith("Building ")
        and not line.startswith("Built ")
        and not line.startswith("Container ")
        and not line.startswith('time="')
    ]
    if filtered_lines:
        lines = filtered_lines

    priority_patterns = [
        "OCI runtime create failed",
        'exec: "python3": executable file not found in $PATH',
        "failed to create task for container",
        "Error response from daemon:",
        "Validating Falco rules...",
        "LOAD_ERR",
        "load_rules",
        "Compilation error",
        "Invalid",
        "invalid",
        "Error:",
        "ERROR",
    ]

    relevant_lines: List[str] = []
    for pattern in priority_patterns:
        for line in lines:
            if pattern in line and line not in relevant_lines:
                relevant_lines.append(line)

    if relevant_lines:
        return "\n".join(relevant_lines[-6:])

    return "\n".join(lines[-VALIDATION_TAIL_LINE_COUNT:])


def _build_user_facing_validation_error(details: str) -> str:
    """Convert raw validator output into a short user-facing error message."""
    normalized_details = details.strip()
    if not normalized_details:
        return "Falco rule validation failed. The custom Falco rules could not be validated."

    if 'exec: "python3": executable file not found in $PATH' in normalized_details:
        return (
            "Falco rule validation is temporarily unavailable because the validator container "
            "could not start correctly."
        )

    lowered = normalized_details.lower()
    if "duplicate" in lowered and "rule" in lowered:
        return (
            "Falco rule validation failed because at least one custom rule name is duplicated. "
            "Use unique rule names and avoid reusing names from the default/community rules."
        )

    if "yaml" in lowered or "invalid" in lowered or "load_err" in lowered or "load_rules" in lowered:
        return (
            "Falco rule validation failed because the custom YAML is not valid for Falco. "
            "Check the YAML syntax and the rule fields."
        )

    return (
        "Falco rule validation failed. The custom Falco rules could not be validated. "
        "Check the YAML syntax and ensure rule names do not collide with existing rules."
    )


def run_falco_rules_validator(rules_config: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validate the temporary custom rules file with an ephemeral Docker Compose service
    that reuses the Falco image and runs `falco --validate` instead of the normal entrypoint.
    """
    cmd = [
        "docker",
        "compose",
        "--profile",
        VALIDATOR_PROFILE,
        "-f",
        str(DATA_COLLECTION_COMPOSE_PATH),
        "run",
        "--rm",
        "--no-deps",
        VALIDATOR_SERVICE_NAME,
    ]

    try:
        completed = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            env=_build_validator_env(rules_config),
            capture_output=True,
            text=True,
            timeout=VALIDATOR_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        cleanup_falco_rules_tmp_file()
        return False, "Falco rule validation timed out."
    except FileNotFoundError as e:
        cleanup_falco_rules_tmp_file()
        return False, f"Could not execute Docker Compose for Falco validation: {e}"
    except Exception as e:
        cleanup_falco_rules_tmp_file()
        return False, f"Unexpected error while validating Falco rules: {e}"

    if completed.returncode == 0:
        return True, ""

    cleanup_falco_rules_tmp_file()
    combined_output = "\n".join(
        part for part in [completed.stdout, completed.stderr] if part and part.strip()
    )
    details = _truncate_validation_output(_extract_relevant_validation_output(combined_output))
    if details:
        return False, f"{_build_user_facing_validation_error(details)}\nDetails: {details}"
    return False, "Falco rule validation failed."


def apply_falco_rules_files(rules_config: Dict[str, Any], validate_custom_rules: bool) -> Tuple[bool, str]:
    """
    Apply the required file lifecycle for the current Falco rules candidate.

    - If there are no custom rules, delete temporary and definitive files.
    - If validation is required, write the temporary file, run the validator,
      and promote it to the definitive file only when validation succeeds.
    - If validation is not required, update the definitive file directly.
    """
    custom_rules = [str(rule) for rule in rules_config.get("custom_rules", [])]

    if not custom_rules:
        try:
            cleanup_falco_rules_files()
            return True, ""
        except Exception as e:
            return False, f"Could not clean Falco custom rules files: {e}"

    if not validate_custom_rules:
        return sync_falco_final_rules_file(rules_config)

    is_written, write_error = write_falco_rules_tmp_file(rules_config)
    if not is_written:
        cleanup_falco_rules_tmp_file()
        return False, write_error

    is_valid, validation_error = run_falco_rules_validator(rules_config)
    if not is_valid:
        return False, validation_error

    return promote_falco_tmp_to_final()
