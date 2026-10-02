#!/usr/bin/env python3
# ============================================================================
#  SARIF Export — Convert SecuAudit findings JSON to SARIF 2.1.0 (CI/CD ready)
#  ---------------------------------------------------------------------------
#  SARIF = Static Analysis Results Interchange Format. Works with GitHub
#  Code Scanning, GitLab SAST, Azure DevOps, SonarQube, and most CI dashboards.
#
#  Usage:
#    python3 sarif_export.py --json scan_results.json --out results.sarif
#    (also auto-invoked by: main.py scan --sarif, main.py audit --sarif)
# ============================================================================

import argparse
import json
import os
import time

SARIF_VERSION = "2.1.0"
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

SEVERITY_MAP = {
    "Critical": "error", "High": "error", "Medium": "warning",
    "Low": "note", "Info": "note",
}


def to_sarif(data: dict, target: str | None = None) -> dict:
    findings = data.get("findings", [])
    tool_name = data.get("tool", "SecuAudit")
    target = target or data.get("target", "unknown-target")

    rules = []
    results = []
    seen_rules = set()

    for f in findings:
        rid = str(f.get("id", "FINDING")).replace(" ", "-")
        if rid not in seen_rules:
            seen_rules.add(rid)
            rules.append({
                "id": rid,
                "name": rid,
                "shortDescription": {"text": str(f.get("title", rid))[:200]},
                "fullDescription": {"text": str(f.get("description", f.get("title", "")))[:400]},
                "help": {"text": str(f.get("remediation", ""))[:1000]},
                "properties": {
                    "severity": f.get("severity", "Info"),
                    "tags": str(f.get("tags", "")).split(",") if f.get("tags") else [],
                },
                "defaultConfiguration": {"level": SEVERITY_MAP.get(f.get("severity", "Info"), "note")},
            })
        level = SEVERITY_MAP.get(f.get("severity", "Info"), "note")
        results.append({
            "ruleId": rid,
            "level": level,
            "message": {"text": str(f.get("title", ""))[:300]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": target},
                    "region": {"startLine": 1, "startColumn": 1},
                }
            }],
            "properties": {
                "evidence": str(f.get("evidence", ""))[:500],
                "remediation": str(f.get("remediation", ""))[:500],
            },
        })

    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "informationUri": "https://github.com/Ainul-550Islam/security-toolkit",
                    "rules": rules,
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": data.get("scan_date", time.strftime("%Y-%m-%dT%H:%M:%SZ")),
            }],
        }],
    }


def write_sarif(data: dict, out_path: str, target: str | None = None):
    sarif = to_sarif(data, target)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)


def main():
    ap = argparse.ArgumentParser(description="Convert findings JSON to SARIF 2.1.0")
    ap.add_argument("--json", required=True)
    ap.add_argument("--out", default="results.sarif")
    ap.add_argument("--target", default=None)
    args = ap.parse_args()

    with open(args.json, encoding="utf-8") as f:
        data = json.load(f)
    write_sarif(data, args.out, args.target)
    print(f"[✓] SARIF written to {args.out}")


if __name__ == "__main__":
    main()
