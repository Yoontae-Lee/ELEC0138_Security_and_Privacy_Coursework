import csv
import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from models import Account, Beneficiary, LoginChallenge, Session, Transaction

DATA_DIR = Path(__file__).parent / "data"
USERS_FILE = DATA_DIR / "users.json"
BENEFICIARIES_FILE = DATA_DIR / "beneficiaries.json"
TRANSACTIONS_FILE = DATA_DIR / "transactions.csv"
AUDIT_LOG_FILE = DATA_DIR / "audit_log.csv"

TRANSACTION_FIELDS = [
    "transaction_id",
    "from_account",
    "to_account",
    "amount",
    "type",
    "status",
    "timestamp",
    "session_id",
    "notes",
]
AUDIT_FIELDS = [
    "timestamp",
    "event_type",
    "user_id",
    "account_id",
    "device_id",
    "location",
    "success",
    "details",
]

TEMP_LOCK_THRESHOLD = 3
PERMANENT_LOCK_THRESHOLD = 6
LOCKOUT_SECONDS = 60

# Defense flags 
# Threat 1 — Account Takeover
DEFENSE_MFA_ENABLED           = os.environ.get("DEFENSE_MFA", "true").lower() == "true"
DEFENSE_LOCKOUT_ENABLED       = os.environ.get("DEFENSE_LOCKOUT", "true").lower() == "true"
DEFENSE_PASSWORD_HASH_ENABLED = os.environ.get("DEFENSE_PASSWORD_HASH", "false").lower() == "true"
DEFENSE_TRANSFER_GUARD_ENABLED = os.environ.get("DEFENSE_TRANSFER_GUARD", "false").lower() == "true"
TRANSFER_GUARD_THRESHOLD      = float(os.environ.get("TRANSFER_GUARD_THRESHOLD", "3000"))

# Threat 2 — HTTP Flood (DoS)
DEFENSE_RATE_LIMIT_ENABLED    = os.environ.get("DEFENSE_RATE_LIMIT", "true").lower() == "true"

def _print_defense_status() -> None:
    flags = [
        ("DEFENSE_MFA",            DEFENSE_MFA_ENABLED),
        ("DEFENSE_LOCKOUT",        DEFENSE_LOCKOUT_ENABLED),
        ("DEFENSE_PASSWORD_HASH",  DEFENSE_PASSWORD_HASH_ENABLED),
        ("DEFENSE_TRANSFER_GUARD", DEFENSE_TRANSFER_GUARD_ENABLED),
        ("DEFENSE_RATE_LIMIT",     DEFENSE_RATE_LIMIT_ENABLED),

    ]
    print("\n  Defense system status:")
    for name, enabled in flags:
        status = "ON" if enabled else "OFF"
        print(f"    {name:<22}: {status}")
    print()

class BankingSystem:
    def __init__(self):
        DATA_DIR.mkdir(exist_ok=True)
        self._accounts: dict[str, Account] = {}
        self._usernames: dict[str, str] = {}
        self._sessions: dict[str, Session] = {}
        self._beneficiaries: dict[str, Beneficiary] = {}
        self._transactions: list[Transaction] = []
        self._pending_logins: dict[str, LoginChallenge] = {}
        self._load_data()

    def start_login(
        self, username: str, password: str, device_id: str, location: str
    ) -> dict:
        account_id = self._usernames.get(username)
        account = self._accounts.get(account_id) if account_id else None

        if DEFENSE_LOCKOUT_ENABLED and account is not None and self._is_permanently_locked(account):
            self._audit(
                "LOGIN_BLOCKED",
                username,
                account_id,
                device_id,
                location,
                success=False,
                details="account_permanently_locked",
            )
            return {
                "ok": False,
                "error": "Account locked after repeated failures. Contact support.",
            }

        if DEFENSE_LOCKOUT_ENABLED and account is not None and self._is_temporarily_locked(account):
            remaining = self._seconds_until_unlock(account)
            self._audit(
                "LOGIN_BLOCKED",
                username,
                account_id,
                device_id,
                location,
                success=False,
                details=f"locked_for={remaining}s",
            )
            return {
                "ok": False,
                "error": f"Too many failed attempts. Try again in {remaining}s.",
            }

        if account is None or not self._verify_password(account.password, password):
            if account is None:
                self._audit(
                    "LOGIN_FAILED",
                    username or "UNKNOWN",
                    "",
                    device_id,
                    location,
                    success=False,
                    details="Bad credentials for unknown user",
                )
                return {"ok": False, "error": "Invalid username or password."}

            attempts = self._record_failed_login(account)
            if self._is_permanently_locked(account):
                error = "Account locked after repeated failures. Contact support."
                details = "Bad credentials;account_permanently_locked"
            elif self._is_temporarily_locked(account):
                remaining = self._seconds_until_unlock(account)
                error = f"Too many failed attempts. Try again in {remaining}s."
                details = f"Bad credentials;locked_for={remaining}s;attempts={attempts}"
            else:
                if attempts < TEMP_LOCK_THRESHOLD:
                    detail_suffix = f"{attempts}/{TEMP_LOCK_THRESHOLD} before temporary lock"
                else:
                    detail_suffix = f"{attempts}/{PERMANENT_LOCK_THRESHOLD} before permanent lock"
                error = f"Invalid username or password. Failed attempts: {detail_suffix}."
                details = f"Bad credentials;attempts={attempts}"

            self._save_users()
            self._audit(
                "LOGIN_FAILED",
                username,
                account_id,
                device_id,
                location,
                success=False,
                details=details,
            )
            return {"ok": False, "error": error}

        self._reset_failed_logins(account)
        trusted_devices = set(account.personal_data.get("trusted_devices", []))
        is_new_device = device_id not in trusted_devices

        # Defense: MFA 
        if not DEFENSE_MFA_ENABLED:
            sess = Session(
                session_id    = str(uuid.uuid4()),
                user_id       = username,
                account_id    = account_id,
                authenticated = True,
                device_id     = device_id,
                location      = location,
                is_new_device = is_new_device,
                mfa_verified  = False,
            )
            self._sessions[sess.session_id] = sess
            self._audit(
                "LOGIN_SUCCESS",
                username,
                account_id,
                device_id,
                location,
                success=True,
                details=f"new_device={is_new_device};mfa=disabled",
            )
            return {"ok": True, "session_id": sess.session_id}

        challenge = LoginChallenge(
            challenge_id=str(uuid.uuid4()),
            user_id=username,
            account_id=account_id,
            device_id=device_id,
            location=location,
            mfa_code=self._generate_mfa_code(),
            is_new_device=is_new_device,
        )
        self._pending_logins[challenge.challenge_id] = challenge
        self._audit(
            "LOGIN_CHALLENGE_ISSUED",
            username,
            account_id,
            device_id,
            location,
            success=True,
            details=f"new_device={is_new_device}",
        )
        return {
            "ok": True,
            "requires_mfa": True,
            "challenge_id": challenge.challenge_id,
            "account_id": account_id,
            "demo_code": challenge.mfa_code,
            "is_new_device": is_new_device,
            "delivery_target": account.personal_data.get("phone", "registered virtual mobile number"),
        }

    def complete_login(self, challenge_id: str, otp_code: str) -> dict:
        challenge = self.get_pending_login(challenge_id)
        if challenge is None:
            return {
                "ok": False,
                "error": "Verification expired. Please sign in again.",
            }

        if otp_code.strip() != challenge.mfa_code:
            challenge.remaining_attempts -= 1
            self._audit(
                "LOGIN_MFA_FAILED",
                challenge.user_id,
                challenge.account_id,
                challenge.device_id,
                challenge.location,
                success=False,
                details=f"remaining_attempts={challenge.remaining_attempts}",
            )
            if challenge.remaining_attempts <= 0:
                self._pending_logins.pop(challenge_id, None)
                return {
                    "ok": False,
                    "error": "Verification failed too many times. Sign in again.",
                }
            return {
                "ok": False,
                "error": (
                    f"Invalid verification code. {challenge.remaining_attempts} "
                    "attempt(s) remaining."
                ),
            }

        account = self._accounts[challenge.account_id]
        trusted_devices = account.personal_data.setdefault("trusted_devices", [])
        if challenge.device_id not in trusted_devices:
            trusted_devices.append(challenge.device_id)
            self._save_users()
            self._audit(
                "DEVICE_TRUSTED",
                challenge.user_id,
                challenge.account_id,
                challenge.device_id,
                challenge.location,
                success=True,
                details="trusted_after_mfa",
            )

        sess = Session(
            session_id=str(uuid.uuid4()),
            user_id=challenge.user_id,
            account_id=challenge.account_id,
            authenticated=True,
            device_id=challenge.device_id,
            location=challenge.location,
            is_new_device=challenge.is_new_device,
            mfa_verified=True,
        )
        self._sessions[sess.session_id] = sess
        self._pending_logins.pop(challenge_id, None)
        self._audit(
            "LOGIN_SUCCESS",
            challenge.user_id,
            challenge.account_id,
            challenge.device_id,
            challenge.location,
            success=True,
            details=f"new_device={challenge.is_new_device};mfa=True",
        )
        return {"ok": True, "session": sess}

    def get_pending_login(self, challenge_id: str) -> Optional[LoginChallenge]:
        challenge = self._pending_logins.get(challenge_id)
        if challenge is None:
            return None
        if challenge.is_expired():
            self._audit(
                "LOGIN_CHALLENGE_EXPIRED",
                challenge.user_id,
                challenge.account_id,
                challenge.device_id,
                challenge.location,
                success=False,
                details="challenge_expired",
            )
            self._pending_logins.pop(challenge_id, None)
            return None
        return challenge

    def discard_pending_login(self, challenge_id: str) -> None:
        self._pending_logins.pop(challenge_id, None)

    def login(
        self, username: str, password: str, device_id: str, location: str
    ) -> Optional[Session]:
        result = self.start_login(username, password, device_id, location)
        if not result.get("ok"):
            return None
        # DEFENSE_MFA=false — session already created, return directly
        if "session_id" in result:
            return self._sessions.get(result["session_id"])
        # DEFENSE_MFA=true — complete MFA challenge
        verified = self.complete_login(result["challenge_id"], result["demo_code"])
        return verified.get("session")

    def invalidate_session(self, session_id: str) -> bool:
        stored = self._sessions.get(session_id)
        if stored is None:
            return False
        stored.authenticated = False
        stored.revoked = True
        stored.logout_time = datetime.utcnow().isoformat()
        self._audit(
            "LOGOUT",
            stored.user_id,
            stored.account_id,
            stored.device_id,
            stored.location,
            success=True,
            details="session_revoked",
        )
        return True

    def view_account(self, session: Session) -> Optional[dict]:
        if not self._validate_session(session, "VIEW_ACCOUNT"):
            return None
        acc = self._accounts[session.account_id]
        return {
            "account_id": acc.account_id,
            "owner": acc.username,
            "balance": acc.balance,
            "personal_data": acc.personal_data,
        }

    def add_beneficiary(
        self, session: Session, target_account: str, nickname: str
    ) -> Optional[Beneficiary]:
        if not self._validate_session(session, "ADD_BENEFICIARY"):
            return None
        bene = Beneficiary(
            beneficiary_id=f"BEN-{uuid.uuid4().hex[:8].upper()}",
            owner_account=session.account_id,
            target_account=target_account,
            nickname=nickname,
        )
        self._beneficiaries[bene.beneficiary_id] = bene
        self._save_beneficiaries()
        self._audit(
            "ADD_BENEFICIARY",
            session.user_id,
            session.account_id,
            session.device_id,
            session.location,
            success=True,
            details=f"beneficiary={target_account};nickname={nickname}",
        )
        return bene

    def transfer(
        self, session: Session, beneficiary_id: str, amount: float
    ) -> Optional[Transaction]:
        if not self._validate_session(session, "TRANSFER_INITIATED"):
            return None

        bene = self._beneficiaries.get(beneficiary_id)
        if bene is None or bene.owner_account != session.account_id:
            self._audit(
                "TRANSFER_FAILED",
                session.user_id,
                session.account_id,
                session.device_id,
                session.location,
                success=False,
                details=f"Unknown beneficiary '{beneficiary_id}'",
            )
            return None

        acc = self._accounts[session.account_id]
        txn = Transaction(
            transaction_id=f"TXN-{uuid.uuid4().hex[:10].upper()}",
            from_account=session.account_id,
            to_account=bene.target_account,
            amount=amount,
            type="TRANSFER",
            status="INITIATED",
            session_id=session.session_id,
        )

        if amount <= 0:
            txn.status = "FAILED"
            txn.notes = "Amount must be greater than £0.00."
            self._record_transaction(txn)
            self._audit(
                "TRANSFER_FAILED",
                session.user_id,
                session.account_id,
                session.device_id,
                session.location,
                success=False,
                details=f"invalid_amount={amount:.2f}",
            )
            return txn

        if DEFENSE_TRANSFER_GUARD_ENABLED and amount > TRANSFER_GUARD_THRESHOLD:
            txn.status = "FAILED"
            txn.notes = (
                f"Warning: transfers above £{TRANSFER_GUARD_THRESHOLD:.2f} are blocked "
                "for manual review. Please lower the amount or request approval."
            )
            self._record_transaction(txn)
            self._audit(
                "TRANSFER_GUARD_BLOCKED",
                session.user_id,
                session.account_id,
                session.device_id,
                session.location,
                success=False,
                details=(
                    f"amount={amount:.2f};threshold={TRANSFER_GUARD_THRESHOLD:.2f};"
                    f"beneficiary={bene.target_account}"
                ),
            )
            return txn

        if acc.balance < amount:
            txn.status = "FAILED"
            txn.notes = "Insufficient funds"
            self._record_transaction(txn)
            self._audit(
                "TRANSFER_FAILED",
                session.user_id,
                session.account_id,
                session.device_id,
                session.location,
                success=False,
                details=f"Insufficient funds;amount={amount:.2f}",
            )
            return txn

        acc.balance -= amount
        txn.status = "COMPLETED"
        self._record_transaction(txn)
        self._save_users()
        self._audit(
            "TRANSFER_COMPLETED",
            session.user_id,
            session.account_id,
            session.device_id,
            session.location,
            success=True,
            details=f"to={bene.target_account};amount={amount:.2f};txn={txn.transaction_id}",
        )
        return txn

    def get_transaction_history(self, session: Session, limit: int = 20) -> list[dict]:
        if not self._validate_session(session, "VIEW_HISTORY"):
            return []
        return [
            t.to_dict()
            for t in reversed(self._transactions)
            if t.from_account == session.account_id or t.to_account == session.account_id
        ][:limit]

    def get_beneficiaries(self, session: Session) -> list[dict]:
        if not self._validate_session(session, "VIEW_BENEFICIARIES"):
            return []
        return [
            b.to_dict()
            for b in self._beneficiaries.values()
            if b.owner_account == session.account_id
        ]

    def create_account(
        self,
        username: str,
        password: str,
        initial_balance: float = 0.0,
        personal_data: Optional[dict] = None,
    ) -> Account:
        profile = dict(personal_data or {})
        profile.setdefault("trusted_devices", [])
        profile.setdefault("security", self._default_security_state())
        acc = Account(
            username=username,
            password=self._prepare_password_for_storage(password),
            account_id=f"ACC-{uuid.uuid4().hex[:8].upper()}",
            balance=initial_balance,
            personal_data=profile,
        )
        self._accounts[acc.account_id] = acc
        self._usernames[acc.username] = acc.account_id
        self._save_users()
        return acc

    def _validate_session(self, session: Session, event_type: str) -> bool:
        stored = self._sessions.get(session.session_id)
        if stored is None or not stored.authenticated or stored.revoked:
            self._audit(
                f"{event_type}_DENIED",
                session.user_id,
                session.account_id,
                session.device_id,
                session.location,
                success=False,
                details="Invalid or expired session",
            )
            return False
        return True

    def _record_transaction(self, txn: Transaction) -> None:
        self._transactions.append(txn)
        with open(TRANSACTIONS_FILE, "a", newline="") as f:
            csv.DictWriter(f, fieldnames=TRANSACTION_FIELDS).writerow(txn.to_dict())

    def _audit(
        self,
        event_type: str,
        user_id: str,
        account_id: str,
        device_id: str,
        location: str,
        success: bool,
        details: str = "",
    ) -> None:
        row = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "account_id": account_id,
            "device_id": device_id,
            "location": location,
            "success": success,
            "details": details,
        }
        with open(AUDIT_LOG_FILE, "a", newline="") as f:
            csv.DictWriter(f, fieldnames=AUDIT_FIELDS).writerow(row)

    def _generate_mfa_code(self) -> str:
        return "".join(secrets.choice("0123456789") for _ in range(6))

    def _prepare_password_for_storage(self, password: str) -> str:
        if DEFENSE_PASSWORD_HASH_ENABLED:
            return self._hash_password(password)
        return password

    def _is_hashed_password(self, stored_password: str) -> bool:
        return isinstance(stored_password, str) and stored_password.startswith("pbkdf2_sha256$")

    def _hash_password(self, password: str, *, iterations: int = 200_000) -> str:
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
        ).hex()
        return f"pbkdf2_sha256${iterations}${salt}${digest}"

    def _verify_password(self, stored_password: str, provided_password: str) -> bool:
        if not isinstance(stored_password, str):
            return False
        if self._is_hashed_password(stored_password):
            try:
                _, iterations_s, salt, digest = stored_password.split("$", 3)
                computed = hashlib.pbkdf2_hmac(
                    "sha256",
                    provided_password.encode("utf-8"),
                    salt.encode("utf-8"),
                    int(iterations_s),
                ).hex()
                return hmac.compare_digest(computed, digest)
            except Exception:
                return False
        return hmac.compare_digest(stored_password, provided_password)

    def _default_security_state(self) -> dict:
        return {
            "failed_login_attempts": 0,
            "locked_until": None,
            "permanently_locked": False,
        }

    def _security_state(self, account: Account) -> dict:
        state = account.personal_data.setdefault("security", self._default_security_state())
        state.setdefault("failed_login_attempts", 0)
        state.setdefault("locked_until", None)
        state.setdefault("permanently_locked", False)
        locked_until = state.get("locked_until")
        if locked_until and isinstance(locked_until, str):
            try:
                expires = datetime.fromisoformat(locked_until)
            except ValueError:
                expires = None
            if expires is not None and expires <= datetime.utcnow():
                state["locked_until"] = None
        return state

    def _record_failed_login(self, account: Account) -> int:
        state = self._security_state(account)
        attempts = int(state.get("failed_login_attempts", 0)) + 1
        state["failed_login_attempts"] = attempts
        if attempts >= PERMANENT_LOCK_THRESHOLD:
            state["permanently_locked"] = True
            state["locked_until"] = None
        elif attempts == TEMP_LOCK_THRESHOLD:
            state["locked_until"] = (
                datetime.utcnow() + timedelta(seconds=LOCKOUT_SECONDS)
            ).isoformat()
        return attempts

    def _reset_failed_logins(self, account: Account) -> None:
        state = self._security_state(account)
        state["failed_login_attempts"] = 0
        state["locked_until"] = None
        state["permanently_locked"] = False
        self._save_users()

    def _is_permanently_locked(self, account: Account) -> bool:
        return bool(self._security_state(account).get("permanently_locked"))

    def _is_temporarily_locked(self, account: Account) -> bool:
        locked_until = self._security_state(account).get("locked_until")
        if not locked_until:
            return False
        try:
            expires = datetime.fromisoformat(locked_until)
        except ValueError:
            return False
        return expires > datetime.utcnow()

    def _seconds_until_unlock(self, account: Account) -> int:
        locked_until = self._security_state(account).get("locked_until")
        if not locked_until:
            return 0
        try:
            expires = datetime.fromisoformat(locked_until)
        except ValueError:
            return 0
        return max(int((expires - datetime.utcnow()).total_seconds()), 0)

    def _load_data(self) -> None:
        if not TRANSACTIONS_FILE.exists():
            with open(TRANSACTIONS_FILE, "w", newline="") as f:
                csv.DictWriter(f, fieldnames=TRANSACTION_FIELDS).writeheader()
        if not AUDIT_LOG_FILE.exists():
            with open(AUDIT_LOG_FILE, "w", newline="") as f:
                csv.DictWriter(f, fieldnames=AUDIT_FIELDS).writeheader()

        if USERS_FILE.exists():
            migrated_passwords = False
            with open(USERS_FILE) as f:
                for item in json.load(f):
                    item.setdefault("personal_data", {})
                    item["personal_data"].setdefault("trusted_devices", [])
                    item["personal_data"].setdefault(
                        "security", self._default_security_state()
                    )
                    if DEFENSE_PASSWORD_HASH_ENABLED and isinstance(item.get("password"), str) and not self._is_hashed_password(item["password"]):
                        item["password"] = self._hash_password(item["password"])
                        migrated_passwords = True
                    acc = Account(**item)
                    self._accounts[acc.account_id] = acc
                    self._usernames[acc.username] = acc.account_id
            if migrated_passwords:
                self._save_users()

        if BENEFICIARIES_FILE.exists():
            with open(BENEFICIARIES_FILE) as f:
                for item in json.load(f):
                    bene = Beneficiary(**item)
                    self._beneficiaries[bene.beneficiary_id] = bene

        if TRANSACTIONS_FILE.exists():
            with open(TRANSACTIONS_FILE, newline="") as f:
                for row in csv.DictReader(f):
                    row["amount"] = float(row["amount"])
                    self._transactions.append(Transaction(**row))

    def _save_users(self) -> None:
        with open(USERS_FILE, "w") as f:
            json.dump([a.to_dict() for a in self._accounts.values()], f, indent=2)

    def _save_beneficiaries(self) -> None:
        with open(BENEFICIARIES_FILE, "w") as f:
            json.dump([b.to_dict() for b in self._beneficiaries.values()], f, indent=2)