#!/usr/bin/env python3
"""
invoke_phase5.py — Phase 5 demo: On-Behalf-Of Identity Propagation.

Two-part demo:
  Part 1 (anti-pattern): Show that admin and operator tokens produce
    identical agent behavior — human identity is invisible.
  Part 2 (fix): Show the JWT claims difference and the one-line code
    change that makes the human role visible to Cedar.

Usage:
    python scripts/invoke_phase5.py
    make phase5
"""

import base64
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv()
load_dotenv(REPO_ROOT / ".env.demo", override=True)

ADMIN_ID_TOKEN = os.environ.get("ADMIN_ID_TOKEN", "")
OPERATOR_ID_TOKEN = os.environ.get("OPERATOR_ID_TOKEN", "")


def decode_jwt(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        payload += "=" * (4 - len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {"error": "Failed to decode JWT"}


def print_claims_comparison(admin_claims: dict, operator_claims: dict) -> None:
    """Side-by-side key fields from admin vs operator tokens."""
    fields = ["sub", "email", "role", "cognito:groups"]
    print(f"  {'Field':<20} {'Admin':<30} {'Operator':<30}")
    print(f"  {'─' * 20} {'─' * 30} {'─' * 30}")
    for f in fields:
        a = str(admin_claims.get(f, "—"))
        o = str(operator_claims.get(f, "—"))
        if a[:28] != o[:28]:
            print(f"  {f:<20} {a[:28]:<30} {o[:28]:<30}  ← DIFFERENT")
        else:
            print(f"  {f:<20} {a[:28]:<30} {o[:28]:<30}")


def main() -> None:
    # ── Part 1: Anti-pattern ─────────────────────────────────────────────
    print("""
╔══════════════════════════════════════════════════════════════╗
║  Phase 5: On-Behalf-Of Identity Propagation                  ║
║  ZT Pillar: Verify Explicitly (end-to-end)                   ║
╚══════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────────┐
│  ANTI-PATTERN (Phases 1–4)                                    │
│                                                               │
│  The agent calls:                                             │
│    get_workload_access_token(workloadName="OrchestratorAgent")│
│                                                               │
│  Result: token carries ONLY the agent's identity.             │
│  Human role (admin vs operator) is invisible to Cedar.        │
│  Both callers get identical behavior — no role enforcement.   │
└──────────────────────────────────────────────────────────────┘
""")

    # ── Part 2: The human tokens ─────────────────────────────────────────
    if not ADMIN_ID_TOKEN or not OPERATOR_ID_TOKEN:
        print("  Tokens not set — run 'make setup' to refresh Cognito tokens.\n")
        return

    admin_claims = decode_jwt(ADMIN_ID_TOKEN)
    operator_claims = decode_jwt(OPERATOR_ID_TOKEN)

    print("  Two humans, two Cognito JWTs — decoded side by side:\n")
    print_claims_comparison(admin_claims, operator_claims)

    print(f"""

  The 'role' field is the key difference (injected by Cognito pre-token Lambda).
  Today (Phases 1–4), this field is LOST after the first agent hop.
  Cedar at ProcurementGateway never sees it.

{'─' * 65}

┌──────────────────────────────────────────────────────────────┐
│  THE FIX — one parameter change                              │
│                                                               │
│  BEFORE:                                                      │
│    token = client.get_workload_access_token(                  │
│        workloadName="OrchestratorAgent"                       │
│    )                                                          │
│                                                               │
│  AFTER:                                                       │
│    token = client.get_workload_access_token_for_jwt(          │
│        workloadName="OrchestratorAgent",                      │
│        userToken=cognito_jwt,  # ← admin or operator JWT     │
│    )                                                          │
│                                                               │
│  The workload token now carries BOTH:                         │
│    agent identity  (sub = workload ARN)                       │
│    human role      (user_role = admin | operator)             │
└──────────────────────────────────────────────────────────────┘

{'─' * 65}
  Cedar policy that becomes enforceable with on-behalf-of:
{'─' * 65}
""")

    policy_path = REPO_ROOT / "policies" / "phase5-approval-obo.cedar"
    if policy_path.exists():
        for line in policy_path.read_text().splitlines():
            print(f"  {line}")
    else:
        print("  policies/phase5-approval-obo.cedar not found")

    print(f"""
{'─' * 65}

  With this policy active:
    admin    + approve_payment → ALLOW  (permit matches user_role=admin)
    operator + approve_payment → DENY   (no permit for operator)

  Same agent. Same tool. Same amount. Same infrastructure.
  One API parameter. The human's role follows the request end-to-end.
""")


if __name__ == "__main__":
    main()
