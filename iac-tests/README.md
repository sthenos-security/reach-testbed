# IaC Security Test Cases

Comprehensive Infrastructure-as-Code test fixtures for REACHABLE scanner.
Exercises every pattern in `IAC_SEVERITY_MAP` across Docker, Kubernetes, and Terraform.

## Expected Behavior

All IaC findings should be classified as:
- **Type:** `CONFIG` (not CWE)
- **Reachability:** `UNKNOWN` (config plane — reachability analysis does not apply)
- **SLA:** ASSESS (no SLA — requires manual review)
- **Severity:** Based on `IAC_SEVERITY_MAP` risk-based mapping, NOT Semgrep raw severity

## Severity Coverage

| Severity | Patterns Covered |
|----------|-----------------|
| CRITICAL | s3-bucket-public, open-to-world, open-cidr, hardcoded-secret, public-access |
| HIGH | privileged, allow-privilege-escalation, hostnetwork, hostpid, host-ipc, missing-user, exposed-service, loadbalancer, capabilities-added |
| MEDIUM | run-as-non-root, read-only-filesystem, seccomp, apparmor, drop-capabilities, missing-network-policy |
| LOW | resource-limit, memory-limit, cpu-limit, liveness-probe, readiness-probe, latest-tag, health-check |

## Structure

```
iac-tests/
├── docker/
│   ├── Dockerfile.insecure          # Missing USER, HEALTHCHECK, latest base
│   ├── Dockerfile.multistage        # Secrets leaked in build layers
│   └── docker-compose.yaml          # Privileged, exposed ports, env secrets
├── kubernetes/
│   ├── privileged-pod.yaml          # Container escape vectors (CRITICAL/HIGH)
│   ├── missing-hardening.yaml       # Missing security context (MEDIUM)
│   ├── missing-best-practices.yaml  # Resource limits, probes (LOW)
│   ├── network-exposure.yaml        # LoadBalancer, missing NetworkPolicy (HIGH/MEDIUM)
│   └── secrets-in-manifests.yaml    # Hardcoded credentials (CRITICAL)
└── terraform/
    ├── s3_public.tf                 # Public buckets, missing encryption (CRITICAL)
    ├── security_groups.tf           # Open CIDR, world-accessible ports (CRITICAL)
    ├── iam_dangerous.tf             # Overly permissive IAM (HIGH)
    ├── ec2_exposed.tf               # Public instances, missing encryption (HIGH)
    └── missing_logging.tf           # Missing audit trails (MEDIUM)
```
