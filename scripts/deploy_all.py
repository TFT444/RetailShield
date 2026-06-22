#!/usr/bin/env python3
"""
RetailShield — One-command deployment script
Deploys all analytics rules to a Microsoft Sentinel workspace via Azure REST API.

Usage:
    python scripts/deploy_all.py --workspace <workspace-name> --resource-group <rg-name>

Requirements:
    pip install azure-identity azure-mgmt-securityinsight
    az login (Azure CLI must be authenticated)
"""

import argparse
import json
import os
import sys
import glob
from pathlib import Path

try:
    from azure.identity import AzureCliCredential
    from azure.mgmt.securityinsight import SecurityInsights
    from azure.mgmt.securityinsight.models import ScheduledAlertRule
except ImportError:
    print("ERROR: Missing dependencies. Run: pip install azure-identity azure-mgmt-securityinsight")
    sys.exit(1)


def get_subscription_id():
    """Get active Azure subscription ID from CLI."""
    import subprocess
    result = subprocess.run(
        ["az", "account", "show", "--query", "id", "-o", "tsv"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("ERROR: Not logged in to Azure CLI. Run: az login")
        sys.exit(1)
    return result.stdout.strip()


def load_arm_templates(rules_dir: Path):
    """Load all analytics rule ARM templates from sentinel/analytics-rules/."""
    templates = []
    pattern = str(rules_dir / "*.json")
    for path in sorted(glob.glob(pattern)):
        with open(path) as f:
            try:
                data = json.load(f)
                templates.append((os.path.basename(path), data))
            except json.JSONDecodeError as e:
                print(f"  WARN: Skipping {path} — invalid JSON: {e}")
    return templates


def deploy_rules(workspace: str, resource_group: str, dry_run: bool = False):
    """Deploy all RetailShield analytics rules to the target Sentinel workspace."""
    repo_root = Path(__file__).parent.parent
    rules_dir = repo_root / "sentinel" / "analytics-rules"

    if not rules_dir.exists():
        print(f"ERROR: Rules directory not found: {rules_dir}")
        sys.exit(1)

    templates = load_arm_templates(rules_dir)
    if not templates:
        print("ERROR: No rule templates found in sentinel/analytics-rules/")
        sys.exit(1)

    print(f"\nRetailShield Deployment")
    print(f"  Workspace:      {workspace}")
    print(f"  Resource group: {resource_group}")
    print(f"  Rules found:    {len(templates)}")
    print(f"  Dry run:        {dry_run}\n")

    if dry_run:
        for name, _ in templates:
            print(f"  [DRY RUN] Would deploy: {name}")
        print(f"\nDry run complete. {len(templates)} rules would be deployed.")
        return

    subscription_id = get_subscription_id()
    credential = AzureCliCredential()
    client = SecurityInsights(credential, subscription_id)

    deployed = 0
    failed = 0

    for name, template in templates:
        rule_name = name.replace(".json", "")
        try:
            resources = template.get("resources", [])
            if not resources:
                print(f"  SKIP {name}: no resources in template")
                continue

            rule_props = resources[0].get("properties", {})
            print(f"  Deploying {rule_name}...", end=" ")

            client.alert_rules.create_or_update(
                resource_group_name=resource_group,
                workspace_name=workspace,
                rule_id=rule_name,
                alert_rule={
                    "kind": "Scheduled",
                    **rule_props
                }
            )
            print("OK")
            deployed += 1

        except Exception as e:
            print(f"FAILED — {e}")
            failed += 1

    print(f"\nDeployment complete: {deployed} deployed, {failed} failed.")
    if failed:
        print("Check Azure Portal > Sentinel > Analytics for any partially deployed rules.")


def main():
    parser = argparse.ArgumentParser(description="Deploy RetailShield to Microsoft Sentinel")
    parser.add_argument("--workspace", required=True, help="Sentinel workspace name")
    parser.add_argument("--resource-group", required=True, help="Azure resource group name")
    parser.add_argument("--dry-run", action="store_true", help="Preview without deploying")
    args = parser.parse_args()

    deploy_rules(
        workspace=args.workspace,
        resource_group=args.resource_group,
        dry_run=args.dry_run
    )


if __name__ == "__main__":
    main()
