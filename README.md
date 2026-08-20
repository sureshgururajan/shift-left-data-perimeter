# Shift-Left AWS Data Perimeter with Orchestration Agents

A working demonstration of shifting AWS data-perimeter validation into pull requests via an Orchestration Agent reviewer, while keeping cloud enforcement deterministic.

## Prerequisites

- **Node.js**: v18+ (Node 20+ recommended)
- **Python**: 3.10+ (3.11 / 3.14 supported)
- **AWS CDK**: Run via `npx cdk` or `npx aws-cdk` (no cloud credentials needed for synthesis/review)

## Project Structure

- `cdk/`: AWS CDK TypeScript application defining S3, IAM roles, and Lambda resources.
- `policies/`:
  - `data_perimeter_objective.json`: Security policy objective (preventing non-org S3 egress).
  - `exception_manifest.json`: Approved vendor exception manifest (e.g., `EXC-2026-04`).
- `agent/`:
  - `agent_reviewer.py`: Contextual Orchestration Agent reviewer evaluating synthesized CloudFormation templates against data perimeter policies and exceptions.
- `tests/`:
  - `test_agent_reviewer.py`: Automated Python unit test suite covering compliant baselines, non-compliant grants, and approved vendor exceptions.
- `.github/workflows/`:
  - `data-perimeter-review.yml`: GitHub Actions workflow posting PR review comments automatically.
- `run_demo.py`: One-command CLI runner for local synthesis and agent review.
- `finding_comment.md`: Output file containing the generated PR review comment.

## Demonstration Lifecycle

### Phase 1: Compliant Baseline (`main` branch)
The CDK stack defines an `s3:PutObject` statement with required organizational condition keys (`aws:PrincipalOrgID` and `aws:ResourceOrgID`).
- **Result:** Status `PASSED` / Compliant.

### Phase 2: Improper PR (`feature/add-lambda-data-processor` branch)
A developer removes the organizational condition keys from the `s3:PutObject` statement.
- **Result:** Status `NEEDS HUMAN REVIEW` / Potential External Exfiltration Path flagged with full remediation steps in `finding_comment.md`.

### Phase 3: Approved Vendor Exception Path
When the data path targets an approved vendor bucket recorded in `policies/exception_manifest.json` (e.g., `arn:aws:s3:::approved-vendor-analytics/*`), the agent identifies the active exception and approves the change.

## Running the Demo

Run the local demo runner:

```bash
python run_demo.py
```

Run the automated test suite:

```bash
python -m unittest discover tests
```
