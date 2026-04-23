# 0. Seed accounts (alice.kim42, bob.lee87 + random users)
# 1. Login from known device
# 2. View account balance
# 3. Add a known beneficiary
# 4. Transfer funds
# 5. View updated balance
# 6. View transaction history
# 7. Failed login attempt

import sys
import os
import random
import string
from pathlib import Path
sys.path.insert(0, os.path.dirname(__file__))
from banking_system import BankingSystem

DATA_DIR = Path(__file__).parent / "data"

# Reference data
FIRST_NAMES = [
    "james", "oliver", "harry", "george", "noah",
    "emma", "olivia", "sophia", "isabella", "mia",
    "william", "thomas", "charlie", "jack", "jacob",
    "emily", "jessica", "sarah", "michael", "david",
]

LAST_NAMES = [
    "smith", "jones", "taylor", "brown", "wilson",
    "davies", "evans", "thomas", "roberts", "johnson",
    "walker", "wright", "robinson", "thompson", "white",
    "harris", "martin", "jackson", "lee", "clark",
]

LOCATIONS = [
    "London, UK",      "Manchester, UK",  "Birmingham, UK",
    "Leeds, UK",       "Glasgow, UK",     "Liverpool, UK",
    "Bristol, UK",     "Edinburgh, UK",   "Sheffield, UK",
    "Cardiff, UK",     "Leicester, UK",   "Nottingham, UK",
    "Newcastle, UK",   "Southampton, UK", "Oxford, UK",
    "Cambridge, UK",   "Brighton, UK",    "Belfast, UK",
    "Aberdeen, UK",    "Coventry, UK",
]

# Clear data files before each run to start fresh
def reset_data():
    files = [
        DATA_DIR / "users.json",
        DATA_DIR / "beneficiaries.json",
        DATA_DIR / "transactions.csv",
        DATA_DIR / "audit_log.csv",
    ]
    for f in files:
        if f.exists():
            f.unlink()
    DATA_DIR.mkdir(exist_ok=True)
    print("  data/ files reset — starting fresh.")

def section(title: str):
    print()
    print("=" * 55)
    print(f"  {title}")
    print("=" * 55)

def show(label: str, data):
    if isinstance(data, dict):
        print(f"\n  [{label}]")
        for k, v in data.items():
            print(f"    {k}: {v}")
    elif isinstance(data, list):
        print(f"\n  [{label}]  ({len(data)} item(s))")
        for item in data:
            print(f"    {item}")
    else:
        print(f"\n  [{label}]  {data}")

def random_username():
    first = random.choice(FIRST_NAMES)
    last  = random.choice(LAST_NAMES)
    num   = random.randint(10, 99)
    return f"{first}.{last}{num}"

def random_password(length=12):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

# Generate random user accounts for realistic environment
def seed_random_accounts(bank: BankingSystem, count: int = 20):
    section(f"STEP 0b — Seed {count} random accounts")
    for i in range(count):
        first    = random.choice(FIRST_NAMES)
        last     = random.choice(LAST_NAMES)
        num      = random.randint(10, 99)
        username = f"{first}.{last}{num}"
        password = random_password()
        balance  = round(random.uniform(100, 15000), 2)
        location = random.choice(LOCATIONS)

        bank.create_account(
            username        = username,
            password        = password,
            initial_balance = balance,
            personal_data   = {
                "name":     f"{first.capitalize()} {last.capitalize()}",
                "email":    f"{username}@example.com",
                "phone":    f"+44-{random.randint(20,191)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}",
                "location": location,
            },
        )
        print(f"    {username:30}  £{balance:>10.2f}  {location}")
    print(f"\n  {count} random accounts created.")


def main():
    reset_data()
    bank = BankingSystem()

    # STEP 0: Seed core accounts
    section("STEP 0 — Seed accounts")

    alice = bank.create_account(
        username        = "alice.kim42",
        password        = "alice_pass_123",
        initial_balance = 5000.00,
        personal_data   = {
            "name":     "Alice Kim",
            "email":    "alice.kim42@example.com",
            "phone":    "+44-20-7946-0101",
            "location": "London, UK",
        },
    )

    bob = bank.create_account(
        username        = "bob.lee87",
        password        = "bob_pass_456",
        initial_balance = 1000.00,
        personal_data   = {
            "name":     "Bob Lee",
            "email":    "bob.lee87@example.com",
            "phone":    "+44-161-496-0102",
            "location": "Manchester, UK",
        },
    )

    # Seed random accounts
    seed_random_accounts(bank, count=150)

    # STEP 1: Login
    section("STEP 1 — Login (known device)")

    sess = bank.login(
        username  = "alice.kim42",
        password  = "alice_pass_123",
        device_id = "DEVICE-ALICE-HOME-001",
        location  = "London, UK",
    )

    if sess is None:
        print("  Login failed — aborting.")
        return

    show("Session", sess.to_dict())

    # STEP 2: View account
    section("STEP 2 — View account")
    show("Account", bank.view_account(sess))

    # STEP 3: Add beneficiary
    section("STEP 3 — Add beneficiary")

    bene = bank.add_beneficiary(
        session        = sess,
        target_account = bob.account_id,
        nickname       = "Bob (friend)",
    )
    show("Beneficiary", bene.to_dict() if bene else "FAILED")

    # STEP 4: Transfer
    section("STEP 4 — Transfer £200 to Bob")

    txn = bank.transfer(
        session        = sess,
        beneficiary_id = bene.beneficiary_id,
        amount         = 200.00,
    )
    show("Transaction", txn.to_dict() if txn else "FAILED")

    # STEP 5: View updated balance
    section("STEP 5 — View updated balance")
    show("Account", bank.view_account(sess))

    # STEP 6: Transaction history
    section("STEP 6 — Transaction history")
    show("History", bank.get_transaction_history(sess))

    # STEP 7: Failed login
    section("STEP 7 — Failed login (wrong password)")

    bad = bank.login(
        username  = "alice.kim42",
        password  = "wrong_password",
        device_id = "DEVICE-UNKNOWN-999",
        location  = "Lagos, NG",
    )
    show("Result", bad or "None — login rejected")

    section("DEMO COMPLETE")
    print()
    print("  Normal workflow verified. Logs written to:")
    print("    data/audit_log.csv")
    print("    data/transactions.csv")
    print()
    print(f"  Total accounts: {len(bank._accounts)}")
    print()
    print("  Ready for attack scripts to be layered on top.")
    print()

if __name__ == "__main__":
    main()