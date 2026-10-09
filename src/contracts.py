"""Portable inventory validation and hypothetical path enumeration (offline only)."""
import argparse
import json
from collections import deque
from pathlib import Path

VERSION = "cyber-defense/inventory/v1"
RELATIONS = {"CAN_REACH", "SELECTS", "USES_IDENTITY", "CAN_READ", "CAN_ASSUME_ROLE", "CAN_INVOKE"}
MAX_RECORDS = 10000

def validate(data):
    if data.get("schema_version") != VERSION:
        raise ValueError("Unsupported inventory schema_version")
    for field in ("producer", "environment_id"):
        if not isinstance(data.get(field), str) or not data[field].strip():
            raise ValueError("Missing " + field)
    assets = data.get("assets")
    edges = data.get("relationships")
    if not isinstance(assets, list) or not isinstance(edges, list) or len(assets) + len(edges) > MAX_RECORDS:
        raise ValueError("Invalid or oversized records")
    ids = set()
    for asset in assets:
        aid = asset.get("id")
        if not isinstance(aid, str) or not aid or aid in ids:
            raise ValueError("Invalid or duplicate asset id")
        ids.add(aid)
    for edge in edges:
        if edge.get("source") not in ids or edge.get("target") not in ids:
            raise ValueError("Unknown relationship endpoint")
        if edge.get("relation") not in RELATIONS:
            raise ValueError("Unknown relationship type")
    for collection in ("entrypoints", "protected_assets"):
        entries = data.get(collection, [])
        if not isinstance(entries, list) or any(e not in ids for e in entries):
            raise ValueError("Invalid " + collection)
    return data

def paths(data, max_depth=8):
    validate(data)
    adj = {}
    for edge in data["relationships"]:
        # Only connectivity edges count as network steps in v1.
        if edge["relation"] == "CAN_REACH":
            adj.setdefault(edge["source"], []).append(edge["target"])
    found = []
    goals = set(data.get("protected_assets", []))
    for start in data.get("entrypoints", []):
        queue = deque([(start, [start])])
        while queue:
            node, path = queue.popleft()
            if node in goals and len(path) > 1:
                found.append({"source": start, "target": node, "nodes": path, "status": "hypothesis"})
                continue
            if len(path) >= max_depth:
                continue
            for dest in sorted(adj.get(node, [])):
                if dest not in path:
                    queue.append((dest, path + [dest]))
    return {"schema_version": "cyber-defense/paths/v1",
            "environment_id": data["environment_id"], "paths": found}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("validate", "paths"))
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--out", type=Path, default=Path("portable-paths.json"))
    args = parser.parse_args()
    if args.inventory.stat().st_size > 2_000_000:
        raise ValueError("Inventory too large")
    obj = validate(json.loads(args.inventory.read_text()))
    if args.action == "paths":
        report = paths(obj)
        args.out.write_text(json.dumps(report, indent=2) + "\n")
        print(f"{len(report['paths'])} hypothetical paths -> {args.out}")
    else:
        print("Valid inventory:", obj["environment_id"])

if __name__ == "__main__":
    main()
