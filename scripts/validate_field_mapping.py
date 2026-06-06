#!/usr/bin/env python3
"""
Validates that every Sentinel analytics rule ARM template in
sentinel/analytics-rules/ has entity mappings and customDetails that
reference columns actually present in the corresponding KQL query output.
"""

import json
import re
import sys
from pathlib import Path

RULES_DIR = Path(__file__).parent.parent / "sentinel" / "analytics-rules"
KQL_DIR = Path(__file__).parent.parent / "detection-rules" / "retail"

REQUIRED_CUSTOM_DETAIL_FIELDS = {"PlaybookTrigger", "RiskScore"}

ERRORS = []
WARNINGS = []


def err(path: str, msg: str) -> None:
    ERRORS.append(f"ERROR  [{path}] {msg}")


def warn(path: str, msg: str) -> None:
    WARNINGS.append(f"WARNING [{path}] {msg}")


def extract_kql_output_columns(kql_text: str) -> set:
    """
    Best-effort extraction of column names from the final KQL project/extend.
    Looks for the last 'project' statement and its column list.
    Falls back to scanning for 'extend ColumnName =' patterns.
    """
    columns = set()

    # Find all 'extend ColumnX = ...' patterns
    for match in re.finditer(r"\bextend\s+([\w]+)\s*=", kql_text):
        columns.add(match.group(1))

    # Find 'project a, b, c' or 'project a = x, b = y'
    for match in re.finditer(r"\bproject\b([^\n|]+)", kql_text):
        for col_expr in match.group(1).split(","):
            col_expr = col_expr.strip()
            # handle 'alias = expr' — take the alias (left side)
            alias_match = re.match(r"^([\w]+)\s*=", col_expr)
            if alias_match:
                columns.add(alias_match.group(1))
            else:
                bare = re.match(r"^([\w]+)$", col_expr)
                if bare:
                    columns.add(bare.group(1))

    # Also pick up summarize output columns
    for match in re.finditer(r"\bsummarize\b([^\n|]+)", kql_text):
        for col_expr in match.group(1).split(","):
            col_expr = col_expr.strip()
            alias_match = re.match(r"^([\w]+)\s*=", col_expr)
            if alias_match:
                columns.add(alias_match.group(1))
            by_match = re.match(r"^by\s+([\w]+)$", col_expr)
            if by_match:
                columns.add(by_match.group(1))

    return columns


def validate_template(json_path: Path) -> bool:
    rule_name = json_path.stem
    path_label = f"sentinel/analytics-rules/{json_path.name}"

    try:
        with open(json_path) as f:
            template = json.load(f)
    except json.JSONDecodeError as e:
        err(path_label, f"Invalid JSON: {e}")
        return False

    resources = template.get("resources", [])
    if not resources:
        err(path_label, "No resources found in template.")
        return False

    resource = resources[0]
    props = resource.get("properties", {})

    # ── 1. Required top-level properties ────────────────────────────────────
    for field in ("displayName", "severity", "query", "queryFrequency",
                  "queryPeriod", "tactics", "techniques", "entityMappings",
                  "customDetails"):
        if field not in props:
            err(path_label, f"Missing required property: '{field}'")

    # ── 2. Severity must be a known value ────────────────────────────────────
    severity = props.get("severity", "")
    if severity not in ("Informational", "Low", "Medium", "High", "Critical"):
        err(path_label, f"Invalid severity '{severity}'")

    # ── 3. queryFrequency / queryPeriod must be ISO 8601 duration ────────────
    for dur_field in ("queryFrequency", "queryPeriod"):
        val = props.get(dur_field, "")
        if not re.match(r"^PT?\d+[MHDS]$", val):
            err(path_label, f"'{dur_field}' is not a valid ISO 8601 duration: '{val}'")

    # ── 4. tactics must be a non-empty list ──────────────────────────────────
    tactics = props.get("tactics", [])
    if not isinstance(tactics, list) or not tactics:
        err(path_label, "tactics must be a non-empty array")

    # ── 5. techniques must be a non-empty list of T-codes ───────────────────
    techniques = props.get("techniques", [])
    if not isinstance(techniques, list) or not techniques:
        err(path_label, "techniques must be a non-empty array")
    for t in techniques:
        if not re.match(r"^T\d{4}(\.\d{3})?$", t):
            err(path_label, f"Technique '{t}' does not match MITRE T#### format")

    # ── 6. entityMappings must be a non-empty list ───────────────────────────
    entity_mappings = props.get("entityMappings", [])
    if not isinstance(entity_mappings, list) or not entity_mappings:
        err(path_label, "entityMappings must be a non-empty array")

    entity_columns = set()
    for em in entity_mappings:
        entity_type = em.get("entityType", "")
        if not entity_type:
            err(path_label, "entityMapping entry missing 'entityType'")
        for fm in em.get("fieldMappings", []):
            col = fm.get("columnName", "")
            if col:
                entity_columns.add(col)
            if not fm.get("identifier"):
                err(path_label, f"fieldMapping for entity '{entity_type}' missing 'identifier'")

    # ── 7. customDetails must include PlaybookTrigger and RiskScore ──────────
    custom_details = props.get("customDetails", {})
    if not isinstance(custom_details, dict):
        err(path_label, "customDetails must be an object")
    else:
        for required in REQUIRED_CUSTOM_DETAIL_FIELDS:
            if required not in custom_details:
                err(path_label, f"customDetails missing required field '{required}'")

    # ── 8. Cross-reference entity mapping columns against KQL output ─────────
    kql_path = KQL_DIR / f"{rule_name}.kql"
    if kql_path.exists():
        with open(kql_path) as f:
            kql_text = f.read()
        kql_columns = extract_kql_output_columns(kql_text)

        if kql_columns:
            for col in entity_columns:
                if col not in kql_columns:
                    warn(
                        path_label,
                        f"Entity mapping references column '{col}' not found in "
                        f"KQL output columns {sorted(kql_columns)}. "
                        "Verify the column name matches exactly."
                    )
            for alias, col in custom_details.items():
                if isinstance(col, str) and col not in kql_columns:
                    warn(
                        path_label,
                        f"customDetails '{alias}' references column '{col}' not found "
                        f"in KQL output columns {sorted(kql_columns)}."
                    )
    else:
        warn(path_label, f"No matching KQL file found at {kql_path} — skipping column cross-check")

    return True


def main() -> int:
    if not RULES_DIR.exists():
        print(f"No analytics rules directory found at {RULES_DIR} — nothing to validate.")
        return 0

    json_files = sorted(RULES_DIR.glob("*.json"))
    if not json_files:
        print(f"ERROR: No JSON files found in {RULES_DIR}", file=sys.stderr)
        return 1

    print(f"Validating {len(json_files)} analytics rule template(s) in {RULES_DIR}\n")

    for json_path in json_files:
        validate_template(json_path)

    if WARNINGS:
        for w in WARNINGS:
            print(w)
        print()

    if ERRORS:
        for e in ERRORS:
            print(e)
        print(f"\n{len(ERRORS)} error(s) found. Fix before merging.")
        return 1

    print(f"All {len(json_files)} analytics rule templates passed field mapping validation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
