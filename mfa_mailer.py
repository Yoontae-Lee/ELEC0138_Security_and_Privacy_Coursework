DEFAULT_MFA_DESTINATION = "registered virtual mobile number"


def normalize_mfa_destination(destination: str | None) -> str:
    if destination and destination.strip():
        return destination.strip()
    return DEFAULT_MFA_DESTINATION


def send_mfa_code(
    code: str,
    username: str,
    device_id: str,
    location: str,
    destination: str | None = None,
) -> tuple[bool, str]:
    normalized_destination = normalize_mfa_destination(destination)
    return False, f"Mock SMS gateway not configured for {normalized_destination}"
