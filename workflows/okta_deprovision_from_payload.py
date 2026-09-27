"""
okta_deprovision_from_payload.py

Reads a leaver JSON payload and deprovisions the corresponding user in Okta:

    1. Load & validate the payload
    2. Look up the Okta user by userPrincipalName
    3. Remove the user from every non-default group they belong to
       (explicit, immediate access revocation -- belt-and-suspenders
       alongside deactivation)
    4. Deactivate the Okta user

Because the Office 365 (Entra ID) app already has "Deactivate Users"
enabled in Provisioning (configured earlier in this build-out), Okta
automatically deactivates the matching Entra ID account as soon as the
Okta user is deactivated -- no separate Graph API call needed here.
Push Groups similarly reflects the group removals into Entra ID on its
next sync.

No new_hires/*.json-style leaver payload exists in the repo yet -- this
schema is a proposed starting point, kept flat and minimal to match the
style of the new-hire payloads on disk. Adjust field names here if you
land on a different schema later.

USAGE
-----
    python okta_deprovision_from_payload.py leavers/leaver_example.json

EXAMPLE PAYLOAD (leavers/leaver_example.json)
-----------------------------------------------
    {
      "userPrincipalName": "aramirez@ntxaerial.com",
      "lastDay": "2026-08-15",
      "reason": "Voluntary resignation"
    }

ENVIRONMENT (.env) -- same as okta_provision_from_payload.py
--------------------------------------------------------------
    OKTA_ORG_URL=https://integrator-7507870.okta.com
    OKTA_API_TOKEN=<your SSWS token>
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

OKTA_ORG_URL = os.environ.get("OKTA_ORG_URL", "").rstrip("/")
OKTA_API_TOKEN = os.environ.get("OKTA_API_TOKEN", "")

if not OKTA_ORG_URL or not OKTA_API_TOKEN:
    sys.exit(
        "Missing OKTA_ORG_URL or OKTA_API_TOKEN. Set them in your .env file.\n"
        "OKTA_ORG_URL should NOT include the '-admin' suffix, e.g.\n"
        "  https://integrator-7507870.okta.com"
    )

HEADERS = {
    "Authorization": f"SSWS {OKTA_API_TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

# Built-in groups every user belongs to that should never be "removed"
SKIP_GROUP_TYPES = {"BUILT_IN"}


# ---------------------------------------------------------------------------
# STEP 01 -- Load & validate payload
# ---------------------------------------------------------------------------
def load_payload(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not data.get("userPrincipalName"):
        sys.exit(f"Payload missing 'userPrincipalName': {path}")
    return data


# ---------------------------------------------------------------------------
# STEP 02 -- Look up the Okta user
# ---------------------------------------------------------------------------
def find_user(upn: str) -> dict[str, Any]:
    print(f"[STEP 02] Looking up Okta user: {upn}")
    resp = requests.get(
        f"{OKTA_ORG_URL}/api/v1/users/{upn}", headers=HEADERS, timeout=30
    )
    if resp.status_code == 404:
        sys.exit(f"No Okta user found with userPrincipalName: {upn}")
    resp.raise_for_status()
    user = resp.json()
    print(f"[STEP 02] Found user: {user['profile']['firstName']} "
          f"{user['profile']['lastName']} (status: {user['status']})")
    return user


# ---------------------------------------------------------------------------
# STEP 03 -- Remove from all non-default groups
# ---------------------------------------------------------------------------
def remove_from_groups(user_id: str) -> None:
    resp = requests.get(
        f"{OKTA_ORG_URL}/api/v1/users/{user_id}/groups", headers=HEADERS, timeout=30
    )
    resp.raise_for_status()
    groups = resp.json()

    if not groups:
        print("[STEP 03] No group memberships to remove.")
        return

    for group in groups:
        gtype = group.get("type")
        name = group["profile"]["name"]
        if gtype in SKIP_GROUP_TYPES:
            print(f"[STEP 03] Skipping built-in group: {name}")
            continue

        del_resp = requests.delete(
            f"{OKTA_ORG_URL}/api/v1/groups/{group['id']}/users/{user_id}",
            headers=HEADERS,
            timeout=30,
        )
        if del_resp.status_code == 204:
            print(f"[STEP 03] Removed from group: {name}")
        else:
            print(f"[STEP 03] WARNING: failed to remove from {name} "
                  f"({del_resp.status_code}): {del_resp.text}")


# ---------------------------------------------------------------------------
# STEP 04 -- Deactivate the Okta user
# ---------------------------------------------------------------------------
def deactivate_user(user_id: str, upn: str) -> None:
    resp = requests.post(
        f"{OKTA_ORG_URL}/api/v1/users/{user_id}/lifecycle/deactivate",
        headers=HEADERS,
        timeout=30,
    )
    if resp.status_code == 200:
        print(f"[STEP 04] Deactivated Okta user: {upn}")
        print("[STEP 04] Entra ID deactivation will follow automatically via "
              "the app's 'Deactivate Users' provisioning setting.")
    else:
        resp.raise_for_status()


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("Usage: python okta_deprovision_from_payload.py <path-to-leaver-payload.json>")

    payload_path = sys.argv[1]

    print(f"[STEP 01] Loading payload: {payload_path}")
    payload = load_payload(payload_path)
    upn = payload["userPrincipalName"]

    if payload.get("lastDay"):
        print(f"[STEP 01] Last day: {payload['lastDay']}")
    if payload.get("reason"):
        print(f"[STEP 01] Reason: {payload['reason']}")

    user = find_user(upn)
    user_id = user["id"]

    if user["status"] in ("DEPROVISIONED", "SUSPENDED"):
        print(f"[STEP 04] User is already {user['status']} -- nothing to do.")
        return

    remove_from_groups(user_id)
    deactivate_user(user_id, upn)

    print(f"[SUCCESS] Deprovisioning complete for {upn}")


if __name__ == "__main__":
    main()
