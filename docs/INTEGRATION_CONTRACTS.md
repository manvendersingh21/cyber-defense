# Integration contracts (v1)

## Design principle
Our graph/planner should not depend on a specific Kubernetes cluster, AWS/Akash setup, exploit runner, datastore, or team's repository. An external adapter exports JSON; the core validates and consumes it. No direct code execution from untrusted adapter input.

## Contracts
Each JSON document includes `schema_version`, `producer`, `environment_id`, and records. IDs are **environment-scoped**. Never put credentials, bearer tokens, real secrets, or sensitive payloads in evidence.

### Inventory (`cyber-defense/inventory/v1`)
`assets` with `id`, `kind`, optional attributes; `relationships` with `source`, `target`, `relation`, `evidence_ids`; `entrypoints` and `protected_assets`. The adapter declares provenance and uncertainty.

### Observations (`cyber-defense/observations/v1`)
`observations`: `source`, `target`, `result` (reachable / blocked / inconclusive), `method`, `timestamp`, and optional evidence IDs. These are observations, not exploit assertions.

### Findings (`cyber-defense/findings/v1`)
Finding IDs, paths, observed outcome, verdict, evidence, proposed follow-up, exploit_verified flag. Produced by the reconciler, not by an external worker's unsupported claim.

### Remediation (future `cyber-defense/remediation/v1`)
Proposal with `finding_id`, proposed change, expected affected graph edges, approval state, test results, and legitimate workflow regression evidence. Never auto-apply changes from imported JSON.

## Adapter expectations
- **Kubernetes**: translate Pods/Services/NetworkPolicy/RBAC into inventory/relationships. Keep platform-specific fields in `attributes`.
- **AWS**: translate IAM grants, VPC routing, security groups, endpoints into the same relationship vocabulary; supply source of each asserted edge.
- **Akash**: represent deployment services, exposed endpoints, and network identity the same way.
- **External teammate's lab**: export a synthetic or explicitly authorized topology; no repo rewrite required.
- **External attack/test runner**: emit bounded observations with method and timestamp; the controller independently reconciles them.

## Trust boundaries
All imported artifacts are untrusted. Validate versions, IDs, endpoint scope, file size, record count, and provenance. Never execute arbitrary shell commands or URLs embedded in input. Separate inferred relationships from measured observations. Store hashes of evidence files when available.

## MVP workflow
```sh
python3 -m src.contracts validate examples/inventory-v1.json
python3 -m src.contracts paths examples/inventory-v1.json --out portable-paths.json
```

This can run without Docker, Kubernetes, a cloud account or third-party packages.

## Graph semantics
A route containing a `CAN_REACH` edge is a **hypothesis** until independently observed. Identity edges such as `CAN_ASSUME_ROLE` or `CAN_READ` are permission assertions; do not equate them with a network hop or confirmed compromise. Later planners must enforce typed edge prerequisites.
