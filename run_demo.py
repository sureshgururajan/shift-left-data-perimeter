#!/usr/bin/env python3
"""
Local CLI runner to test CDK synthesis and Orchestration Agent review locally.
"""

import subprocess
import os
import sys

def run_command(command, cwd=None):
    print(f"[Run] {command}")
    res = subprocess.run(command, shell=True, cwd=cwd, text=True, capture_output=True)
    if res.returncode != 0:
        print(f"[Error] Command failed with exit code {res.returncode}")
        print(res.stdout)
        print(res.stderr)
        return False
    print(res.stdout)
    return True

def main():
    print("============================================================")
    print("   Shift-Left Data Perimeter Orchestration Agent Demo Runner")
    print("============================================================")

    cdk_dir = os.path.join(os.getcwd(), "cdk")

    # Step 1: Synthesize CDK stack
    print("\n[Step 1] Running CDK Synthesis...")
    if not run_command("npx aws-cdk synth", cwd=cdk_dir):
        sys.exit(1)

    # Step 2: Run Orchestration Agent Reviewer
    print("\n[Step 2] Executing Contextual Orchestration Agent Reviewer...")
    python_exe = sys.executable
    template_path = os.path.join("cdk", "cdk.out", "DataPerimeterStack.template.json")
    if not run_command(f'"{python_exe}" agent/agent_reviewer.py "{template_path}"'):
        sys.exit(1)

    print("\n[Complete] Demo run finished successfully. See finding_comment.md for PR comment preview.")

if __name__ == "__main__":
    main()
