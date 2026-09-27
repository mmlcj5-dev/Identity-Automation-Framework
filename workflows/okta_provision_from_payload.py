"""
okta_provision_from_payload.py

Reads a new-hire JSON payload (matching the Identity-Automation-Framework
new_hires/*.json schema) and provisions the corresponding user in Okta:

    1. Load & validate the payload
    2. Resolve target Okta groups via a local rules engine
       (mirrors modules/okta_rules_engine.py: job_title + department + shift
       -> group list)
    3. Create the Okta user (POST /api/v1/users)
    4. Ensure each resolved group exists in Okta (create if missing)
    5. Add the user to each resolved group

This is the "Okta as joiner trigger" step that sits upstream of the existing
graph_users.py / graph_groups.py Entra ID provisioning in the framework.
Once a user + groups exist in Okta, the Office 365 app's Provisioning and
Push Groups features (already configured) carry them into Entra ID
automatically -- no Graph API code needed on this side of the pipeline.

USAGE
-----
    python okta_provision_from_payload.py new_hires/newhire_drone_pilot.json

ENVIRONMENT (.env)
-------------------
    OKTA_ORG_URL=https://integrator-7507870.okta.com
    OKTA_API_TOKEN=<your SSWS token from Security > API > Tokens>

NOTE on OKTA_ORG_URL: the admin console URL has a "-admin" suffix
(integrator-7507870-admin.okta.com) but the API base URL does NOT --
use https://integrator-7507870.okta.com for OKTA_ORG_URL.
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


# ---------------------------------------------------------------------------
# STEP 03 (mirrors modules/okta_rules_engine.py) -- role-to-group mapping
# ---------------------------------------------------------------------------
# NOTE: the actual new_hires/*.json files on disk use a flat schema
# (firstName, lastName, title, department, userPrincipalName, ...) rather
# than the nested "employee: {...}" schema the README documents. This
# script matches what's actually in the repo. Update DEPT_MAP below as
# you confirm the department values used across the other payload files.
DEPT_MAP: dict[str, list[str]] = {
    "Drone Operations": ["grp-flight-ops", "grp-field-staff"],
    "Flight Operations": ["grp-flight-ops", "grp-field-staff"],
    "Engineering": ["grp-engineering", "grp-tech-staff"],
    "Logistics": ["grp-logistics"],
}


def resolve_groups(employee: dict[str, Any]) -> list[str]:
    """Map title + department -> list of Okta group names."""
    department = employee.get("department", "")

    groups = ["grp-all-staff"]
    groups.extend(DEPT_MAP.get(department, []))

    if department not in DEPT_MAP:
        print(f"[STEP 03] WARNING: no group mapping for department "
              f"'{department}' -- only grp-all-staff will be assigned. "
              f"Add it to DEPT_MAP in this script.")

    # De-duplicate while preserving order
    seen = set()
    ordered = []
    for g in groups:
        if g not in seen:
            seen.add(g)
            ordered.append(g)
    return ordered


# ---------------------------------------------------------------------------
# STEP 01 -- Load payload
# ---------------------------------------------------------------------------
def load_payload(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Support both the flat schema actually on disk and the nested
    # "employee: {...}" schema the README documents, in case files are
    # migrated to that shape later.
    return data.get("employee", data)


# ---------------------------------------------------------------------------
# STEP 02 -- Validate required fields
# ---------------------------------------------------------------------------
REQUIRED_FIELDS = ["firstName", "lastName", "title", "department"]


def validate_employee(employee: dict[str, Any]) -> None:
    missing = [f for f in REQUIRED_FIELDS if not employee.get(f)]
    if missing:
        sys.exit(f"Payload missing required field(s): {', '.join(missing)}")


# ---------------------------------------------------------------------------
# STEP 04 -- Create Okta user
# ---------------------------------------------------------------------------
def create_okta_user(employee: dict[str, Any]) -> dict[str, Any]:
    first = employee["firstName"]
    last = employee["lastName"]
    # Prefer the UPN already supplied in the payload; fall back to the
    # firstname.lastname convention if a payload ever omits it.
    upn = employee.get("userPrincipalName") or f"{first.lower()}.{last.lower()}@ntxaerial.com"

    profile = {
        "firstName": first,
        "lastName": last,
        "email": upn,
        "login": upn,
        "title": employee.get("title"),
        "department": employee.get("department"),
    }
    if employee.get("mailNickname"):
        profile["nickName"] = employee["mailNickname"]

    body: dict[str, Any] = {"profile": profile}

    # If the payload includes a temporary password, set it and require a
    # change on first login rather than sending an activation email.
    if employee.get("temporaryPassword"):
        body["credentials"] = {
            "password": {"value": employee["temporaryPassword"]}
        }

    print(f"[STEP 04] Creating Okta user: {upn}")
    resp = requests.post(
        f"{OKTA_ORG_URL}/api/v1/users?activate=true",
        headers=HEADERS,
        json=body,
        timeout=30,
    )

    if resp.status_code == 200:
        print(f"[STEP 04] Okta user created: {upn}")
        return resp.json()

    if resp.status_code == 400 and "login" in resp.text and "unique" in resp.text.lower():
        print(f"[STEP 04] User already exists, fetching existing record: {upn}")
        lookup = requests.get(
            f"{OKTA_ORG_URL}/api/v1/users/{upn}", headers=HEADERS, timeout=30
        )
        lookup.raise_for_status()
        return lookup.json()

    resp.raise_for_status()
    return {}  # unreachable, raise_for_status will throw


# ---------------------------------------------------------------------------
# STEP 05a -- Ensure group exists (create if missing)
# ---------------------------------------------------------------------------
def get_or_create_group(name: str) -> str:
    """Return the Okta group ID for `name`, creating the group if needed."""
    search = requests.get(
        f"{OKTA_ORG_URL}/api/v1/groups",
        headers=HEADERS,
        params={"q": name},
        timeout=30,
    )
    search.raise_for_status()
    for group in search.json():
        if group["profile"]["name"] == name:
            return group["id"]

    print(f"[STEP 05] Group not found, creating: {name}")
    body = {
        "profile": {
            "name": name,
            "description": f"Auto-created by okta_provision_from_payload.py ({name})",
        }
    }
    create = requests.post(
        f"{OKTA_ORG_URL}/api/v1/groups", headers=HEADERS, json=body, timeout=30
    )
    create.raise_for_status()
    return create.json()["id"]


# ---------------------------------------------------------------------------
# STEP 05b -- Add user to group
# ---------------------------------------------------------------------------
def add_user_to_group(user_id: str, group_id: str, group_name: str) -> None:
    resp = requests.put(
        f"{OKTA_ORG_URL}/api/v1/groups/{group_id}/users/{user_id}",
        headers=HEADERS,
        timeout=30,
    )
    if resp.status_code == 204:
        print(f"[STEP 05] Added to group: {group_name}")
    else:
        print(f"[STEP 05] WARNING: failed to add to {group_name} "
              f"({resp.status_code}): {resp.text}")


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("Usage: python okta_provision_from_payload.py <path-to-payload.json>")

    payload_path = sys.argv[1]

    print(f"[STEP 01] Loading payload: {payload_path}")
    employee = load_payload(payload_path)

    print(f"[STEP 02] Validating: {employee['firstName']} {employee['lastName']} "
          f"| {employee['title']} | {employee['department']}")
    validate_employee(employee)

    groups = resolve_groups(employee)
    print(f"[STEP 03] Rules engine resolved {len(groups)} group(s): {', '.join(groups)}")

    user = create_okta_user(employee)
    user_id = user["id"]

    for group_name in groups:
        group_id = get_or_create_group(group_name)
        add_user_to_group(user_id, group_id, group_name)

    print(f"[SUCCESS] Provisioning complete for "
          f"{employee['firstName']} {employee['lastName']} "
          f"({user['profile']['login']})")


if __name__ == "__main__":
    main()
