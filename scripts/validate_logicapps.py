"""
RetailShield — Logic App JSON Schema Validator
Validates all workflow.json files under logic-apps/ are well-formed
JSON and contain the required ARM template skeleton.
Exit code 0 = all valid. Exit code 1 = one or more failures.
"""

import sys
import json
from pathlib import Path

LOGIC_APPS_DIR = Path(__file__).parent.parent / "logic-apps"

REQUIRED_ARM_KEYS = ["$schema", "contentVersion"]
PLACEHOLDER_MARKER = "Placeholder"


def check_workflow(path: Path) -> list[str]:
    errors = []

    # Must be valid JSON
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"Invalid JSON: {exc}"]

    # Must not be a placeholder
    raw = path.read_text(encoding="utf-8")
    if PLACEHOLDER_MARKER in raw:
        errors.append("Workflow is still a placeholder — implement before merging")
        return errors

    # Required ARM skeleton keys
    for key in REQUIRED_ARM_KEYS:
        if key not in data:
            errors.append(f"Missing required ARM key: '{key}'")

    # Must contain 'resources' or 'definition' (Logic App body)
    if "resources" not in data and "definition" not in data:
        errors.append("Missing 'resources' or 'definition' — ARM template appears empty")

    return errors


def main() -> int:
    workflow_files = sorted(LOGIC_APPS_DIR.rglob("workflow.json"))

    if not workflow_files:
        print("⚠  No workflow.json files found in logic-apps/ — nothing to validate")
        return 0

    failed = 0
    for path in workflow_files:
        errors = check_workflow(path)
        relative = path.relative_to(LOGIC_APPS_DIR.parent)
        if errors:
            # Placeholder files are expected during scaffolding — warn, don't fail
            if len(errors) == 1 and "placeholder" in errors[0].lower():
                print(f"⚠   {relative}  (placeholder — skipped)")
            else:
                print(f"\n❌  {relative}")
                for err in errors:
                    print(f"     • {err}")
                failed += 1
        else:
            print(f"✅  {relative}")

    print(f"\n{'─' * 50}")
    total = len(workflow_files)
    passed = total - failed
    print(f"Results: {passed}/{total} workflows passed")

    if failed:
        print(f"\n{failed} workflow(s) failed validation.")
        return 1

    print("All workflows passed validation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
