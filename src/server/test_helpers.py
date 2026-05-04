"""Shared test helpers."""
from itsdangerous import URLSafeSerializer

_SIGNER = URLSafeSerializer("dev-secret-key-change-in-production", salt="session")


def make_session(login_user_id: str, login_username: str, login_display_name: str,
                 active_namespace_id: str, active_display_name: str) -> str:
    return _SIGNER.dumps({
        "authenticated": True,
        "login_user_id": login_user_id,
        "login_username": login_username,
        "login_display_name": login_display_name,
        "active_namespace_id": active_namespace_id,
        "active_display_name": active_display_name,
        "active_user_id": active_namespace_id,
        "active_username": active_display_name,
    })
