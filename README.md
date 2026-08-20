# Shift-Left Organizational Trust Boundary Enforcement with Orchestration Agents

A working demonstration of moving organizational trust-boundary validation into pull requests via an Orchestration Agent reviewer, while keeping cloud enforcement deterministic and machine-checked.

## Overview

Organizational trust boundaries (spanning identity, resource, and network control objectives) frequently fail when validation occurs after deployment. This repository demonstrates a 4-layer architecture that combines deterministic static analysis, LLM-based orchestration agent contextual review, human approval, and deterministic cloud enforcement controls (SCPs, RCPs, IAM, and Endpoint policies).

## Prerequisites

- **Node.js**: v18+ (Node 20+ recommended)
- **Python**: 3.10+ (3.11 / 3.14 supported)
- **AWS CDK**: Run via `npx cdk` or `npx aws-cdk` (no cloud credentials needed for synthesis/review)

## Project Structure

- `cdk/`: AWS CDK TypeScript application defining S3, IAM roles, and Lambda resources as a concrete implementation platform.
- `policies/`:
  - `data_perimeter_objective.json`: Security policy objective (preventing non-org data egress).
  - `exception_manifest.json`: Approved vendor exception manifest (e.g., `EXC-2026-04`).
- `agent/`:
  - `agent_reviewer.py`: Contextual Orchestration Agent reviewer evaluating synthesized CloudFormation templates against policy objectives and exception manifests.
- `tests/`:
  - `test_agent_reviewer.py`: Automated Python unit test suite covering compliant baselines, non-compliant grants, and approved vendor exceptions.
- `.github/workflows/`:
  - `data-perimeter-review.yml`: GitHub Actions workflow posting/updating PR review comments automatically without duplication.
- `run_demo.py`: One-command CLI runner for local synthesis and agent review.
- `finding_comment.md`: Output file containing the generated PR review comment.

## Demonstration Lifecycle

### 1. Compliant Baseline (`main` branch)
The CDK stack defines a write statement with required organizational condition keys (`aws:PrincipalOrgID` and `aws:ResourceOrgID`).
- **Result:** Status `PASSED` / Compliant.

### 2. Flawed PR (`feature/unconstrained-s3-write-grant` branch)
A developer removes organizational condition keys from the write statement.
- **Result:** Status `NEEDS HUMAN REVIEW` / Potential External Exfiltration Path flagged with full remediation steps.

### 3. Approved Vendor Exception Path (`feature/approved-vendor-export` branch)
When the data path targets an approved vendor bucket recorded in `policies/exception_manifest.json` (e.g., `arn:aws:s3:::approved-vendor-analytics/*`), the agent matches the active exception and approves the change.

## Running the Demo

Run the local demo runner:

```bash
python run_demo.py
```

Run the automated test suite:

```bash
python -m unittest discover tests
```
