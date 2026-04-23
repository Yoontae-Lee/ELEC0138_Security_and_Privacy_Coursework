from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

@dataclass
class Account:
    username: str
    password: str
    account_id: str
    balance: float
    personal_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "password": self.password,
            "account_id": self.account_id,
            "balance": self.balance,
            "personal_data": self.personal_data,
        }

@dataclass
class Session:
    session_id: str
    user_id: str
    account_id: str
    authenticated: bool
    device_id: str
    location: str
    login_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    is_new_device: bool = False
    mfa_verified: bool = False
    revoked: bool = False
    logout_time: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "account_id": self.account_id,
            "authenticated": self.authenticated,
            "device_id": self.device_id,
            "location": self.location,
            "login_time": self.login_time,
            "is_new_device": self.is_new_device,
            "mfa_verified": self.mfa_verified,
            "revoked": self.revoked,
            "logout_time": self.logout_time,
        }


@dataclass
class LoginChallenge:
    challenge_id: str
    user_id: str
    account_id: str
    device_id: str
    location: str
    mfa_code: str
    is_new_device: bool
    issued_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    expires_at: str = field(
        default_factory=lambda: (datetime.utcnow() + timedelta(minutes=5)).isoformat()
    )
    remaining_attempts: int = 3

    def is_expired(self) -> bool:
        return datetime.utcnow() >= datetime.fromisoformat(self.expires_at)


@dataclass
class Beneficiary:
    beneficiary_id: str
    owner_account: str
    target_account: str
    nickname: str
    added_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "beneficiary_id": self.beneficiary_id,
            "owner_account": self.owner_account,
            "target_account": self.target_account,
            "nickname": self.nickname,
            "added_at": self.added_at,
        }


@dataclass
class Transaction:
    transaction_id: str
    from_account: str
    to_account: str
    amount: float
    type: str
    status: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    session_id: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "transaction_id": self.transaction_id,
            "from_account": self.from_account,
            "to_account": self.to_account,
            "amount": self.amount,
            "type": self.type,
            "status": self.status,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "notes": self.notes,
        }
