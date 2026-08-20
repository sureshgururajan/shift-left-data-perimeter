# Shift-Left AWS Data Perimeter with Orchestration Agents

A working demonstration of shifting AWS data-perimeter validation into pull requests via an Orchestration Agent reviewer, while keeping cloud enforcement deterministic.

## Prerequisites

- **Node.js**: v18+ (v26.5.1 verified)
- **Python**: 3.10+ (3.14 verified)
- **AWS CDK**: Run via `npx cdk` (no credentials needed for synthesis)

## Project Structure

- `cdk/`: AWS CDK application defining S3 and Lambda resources.
- `policies/`: Security policy objectives (`data_perimeter_objective.json`) and vendor exception manifest (`exception_manifest.json`).
- `agent/`: Contextual Orchestration Agent reviewer (`agent_reviewer.py`).
- `.github/workflows/`: GitHub Actions workflow for PR automated reviews (`data-perimeter-review.yml`).
- `run_demo.py`: One-command CLI runner for local testing.

## Local Execution

Run the demo runner locally to test CDK synthesis and agent review:

```bash
python run_demo.py
```

- **Phase 1 Baseline (`main` branch):** The agent reports `Compliant` status because `aws:PrincipalOrgID` / `aws:ResourceOrgID` conditions are present.
- **Phase 2 Flawed PR (`feature/...` branch):** When an unconstrained `s3:PutObject` grant is introduced, the agent flags `NEEDS HUMAN REVIEW` and outputs the structured PR Finding.
