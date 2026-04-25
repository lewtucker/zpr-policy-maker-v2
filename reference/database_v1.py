"""SQLite persistence — RFC-15.5 clean schema (v2).

Tables
------
- ``schema_meta`` — single-row config; holds ``schema_version``
- ``users`` — per-user account + ZPL data
- ``check_log`` — one row per /check call (activity stream)
- ``approvals`` — pending approval requests

Per-user YAML columns
---------------------
- ``rules_yaml``    — ZPL rules (new rule shape matching RFC-15.5 BNF)
- ``classes_yaml``  — user-defined subclasses (rooted at users/endpoints/services)
- ``entities_yaml`` — named instances (users/services/endpoints with concrete attrs)

Per-user settings
-----------------
- ``password_hash``, ``agent_token``, ``created_at``
- ``eval_mode`` (``never-precedence`` default)
- ``verbs_json`` (user-added verbs)
- ``prompts_json`` (prompt name → override text; unified replacement for the
  old ``skill_text`` + ``generate_skill_text`` columns)

This module does not attempt to migrate v1 databases in-place. If the
database file exists but lacks ``schema_meta``, :func:`init_db` raises
``SchemaVersionError`` with instructions to move the old file aside.
"""
from __future__ import annotations

import json
import os
import secrets as _secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "2"

_server_dir = Path(__file__).parent
DB_PATH = (
    Path("/tmp/policy_maker.db") if os.environ.get("VERCEL") else _server_dir / "policy_maker.db"
)

EMPTY_RULES_YAML = "rules: []\n"
EMPTY_CLASSES_YAML = "classes: []\n"
EMPTY_ENTITIES_YAML = "entities: []\n"


class SchemaVersionError(RuntimeError):
    """Raised when the database file exists but is not v2."""


# ── Connection ──────────────────────────────────────────────────────────────


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Schema lifecycle ────────────────────────────────────────────────────────


def init_db() -> None:
    """Create tables on a fresh database, or verify schema version on an existing one.

    Raises:
        SchemaVersionError: if DB exists but is not v2 (typically a v1 database
            from before the RFC-15.5 rewrite).
    """
    db_exists = DB_PATH.exists() and DB_PATH.stat().st_size > 0

    with _conn() as conn:
        # Create schema_meta first so fresh installs can be tagged v2
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )

        if db_exists:
            row = conn.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is None:
                raise SchemaVersionError(
                    f"Database at {DB_PATH} predates the RFC-15.5 rewrite "
                    f"(no schema_meta row). Move or delete the file to proceed:\n"
                    f"    mv {DB_PATH} {DB_PATH}.v1-backup"
                )
            if row["value"] != SCHEMA_VERSION:
                raise SchemaVersionError(
                    f"Database at {DB_PATH} has schema_version={row['value']!r}, "
                    f"expected {SCHEMA_VERSION!r}"
                )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                email         TEXT PRIMARY KEY,
                password_hash TEXT,
                agent_token   TEXT,
                created_at    TEXT NOT NULL,
                rules_yaml    TEXT NOT NULL DEFAULT 'rules: []\n',
                classes_yaml  TEXT NOT NULL DEFAULT 'classes: []\n',
                entities_yaml TEXT NOT NULL DEFAULT 'entities: []\n',
                eval_mode     TEXT NOT NULL DEFAULT 'never-precedence',
                verbs_json    TEXT NOT NULL DEFAULT '[]',
                prompts_json  TEXT NOT NULL DEFAULT '{}'
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS check_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                email       TEXT NOT NULL,
                ts          TEXT NOT NULL,
                tool        TEXT NOT NULL,
                params_json TEXT NOT NULL DEFAULT '{}',
                verdict     TEXT NOT NULL,
                rule_id     TEXT,
                rule_name   TEXT,
                token       TEXT
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS approvals (
                id          TEXT PRIMARY KEY,
                email       TEXT NOT NULL,
                tool        TEXT NOT NULL,
                params_json TEXT NOT NULL DEFAULT '{}',
                rule_id     TEXT,
                rule_name   TEXT,
                subject_id  TEXT,
                created_at  TEXT NOT NULL,
                verdict     TEXT,
                reason      TEXT,
                resolved_at TEXT
            )
            """
        )

        # Add notes_text column if this is an older v2 DB that predates it
        existing = {
            row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()
        }
        if "notes_text" not in existing:
            conn.execute("ALTER TABLE users ADD COLUMN notes_text TEXT NOT NULL DEFAULT ''")

        # Tag the schema version (no-op on re-init)
        conn.execute(
            "INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', ?)",
            (SCHEMA_VERSION,),
        )
        conn.commit()


# ── Users ───────────────────────────────────────────────────────────────────


def get_user(email: str) -> sqlite3.Row | None:
    with _conn() as conn:
        return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def create_user(email: str) -> None:
    token = _secrets.token_hex(32)
    with _conn() as conn:
        conn.execute(
            "INSERT INTO users (email, agent_token, created_at) VALUES (?, ?, ?)",
            (email, token, _now()),
        )
        conn.commit()


def get_or_create_user(email: str) -> sqlite3.Row:
    user = get_user(email)
    if user is None:
        create_user(email)
        user = get_user(email)
        assert user is not None
    return user


def delete_user(email: str) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM check_log WHERE email = ?", (email,))
        conn.execute("DELETE FROM approvals WHERE email = ?", (email,))
        conn.execute("DELETE FROM users WHERE email = ?", (email,))
        conn.commit()


def get_all_users_with_activity() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            """
            SELECT u.email, u.created_at, MAX(c.ts) as last_activity
            FROM users u
            LEFT JOIN check_log c ON c.email = u.email
            GROUP BY u.email
            ORDER BY last_activity IS NULL ASC, last_activity DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]


# ── Per-user YAML: rules / classes / entities ───────────────────────────────


def get_rules_yaml(email: str) -> str:
    user = get_user(email)
    return (user["rules_yaml"] if user else None) or EMPTY_RULES_YAML


def save_rules(email: str, yaml_str: str) -> None:
    with _conn() as conn:
        conn.execute("UPDATE users SET rules_yaml = ? WHERE email = ?", (yaml_str, email))
        conn.commit()


def get_classes_yaml(email: str) -> str:
    user = get_user(email)
    return (user["classes_yaml"] if user else None) or EMPTY_CLASSES_YAML


def save_classes(email: str, yaml_str: str) -> None:
    with _conn() as conn:
        conn.execute("UPDATE users SET classes_yaml = ? WHERE email = ?", (yaml_str, email))
        conn.commit()


def get_entities_yaml(email: str) -> str:
    user = get_user(email)
    return (user["entities_yaml"] if user else None) or EMPTY_ENTITIES_YAML


def save_entities(email: str, yaml_str: str) -> None:
    with _conn() as conn:
        conn.execute("UPDATE users SET entities_yaml = ? WHERE email = ?", (yaml_str, email))
        conn.commit()


# ── Auth: agent token, password ─────────────────────────────────────────────


def get_agent_token(email: str) -> str | None:
    user = get_user(email)
    return user["agent_token"] if user else None


def save_agent_token(email: str, token: str) -> None:
    with _conn() as conn:
        conn.execute("UPDATE users SET agent_token = ? WHERE email = ?", (token, email))
        conn.commit()


def get_email_by_token(token: str) -> str | None:
    with _conn() as conn:
        row = conn.execute("SELECT email FROM users WHERE agent_token = ?", (token,)).fetchone()
        return row["email"] if row else None


def get_password_hash(email: str) -> str | None:
    user = get_user(email)
    return user["password_hash"] if user else None


def set_password_hash(email: str, password_hash: str) -> None:
    with _conn() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE email = ?", (password_hash, email)
        )
        conn.commit()


# ── Settings: eval mode, custom verbs ───────────────────────────────────────


def get_eval_mode(email: str) -> str:
    user = get_user(email)
    return (user["eval_mode"] if user else None) or "never-precedence"


def save_eval_mode(email: str, mode: str) -> None:
    with _conn() as conn:
        conn.execute("UPDATE users SET eval_mode = ? WHERE email = ?", (mode, email))
        conn.commit()


def get_custom_verbs(email: str) -> list[str]:
    user = get_user(email)
    if not user or not user["verbs_json"]:
        return []
    try:
        return json.loads(user["verbs_json"])
    except json.JSONDecodeError:
        return []


def save_custom_verbs(email: str, verbs: list[str]) -> None:
    with _conn() as conn:
        conn.execute(
            "UPDATE users SET verbs_json = ? WHERE email = ?", (json.dumps(verbs), email)
        )
        conn.commit()


def get_notes(email: str) -> str:
    user = get_user(email)
    return (user["notes_text"] if user else None) or ""


def save_notes(email: str, text: str) -> None:
    with _conn() as conn:
        conn.execute("UPDATE users SET notes_text = ? WHERE email = ?", (text, email))
        conn.commit()


# ── Prompt overrides (unified replacement for skill_text / generate_skill_text) ─


def get_prompt_override(email: str, name: str) -> str | None:
    user = get_user(email)
    if user is None:
        return None
    try:
        d = json.loads(user["prompts_json"] or "{}")
    except json.JSONDecodeError:
        return None
    return d.get(name) or None


def save_prompt_override(email: str, name: str, text: str) -> None:
    user = get_user(email)
    if user is None:
        return
    try:
        d = json.loads(user["prompts_json"] or "{}")
    except json.JSONDecodeError:
        d = {}
    d[name] = text
    with _conn() as conn:
        conn.execute(
            "UPDATE users SET prompts_json = ? WHERE email = ?", (json.dumps(d), email)
        )
        conn.commit()


def clear_prompt_override(email: str, name: str) -> None:
    user = get_user(email)
    if user is None:
        return
    try:
        d = json.loads(user["prompts_json"] or "{}")
    except json.JSONDecodeError:
        d = {}
    d.pop(name, None)
    with _conn() as conn:
        conn.execute(
            "UPDATE users SET prompts_json = ? WHERE email = ?", (json.dumps(d), email)
        )
        conn.commit()


# ── Check log ───────────────────────────────────────────────────────────────


def log_check(
    email: str,
    tool: str,
    params_json: str,
    verdict: str,
    rule_id: str | None,
    rule_name: str | None,
    token: str | None = None,
) -> None:
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO check_log (email, ts, tool, params_json, verdict, rule_id, rule_name, token)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (email, _now(), tool, params_json, verdict, rule_id, rule_name, token),
        )
        conn.commit()


def get_check_log(email: str, limit: int = 50) -> list[sqlite3.Row]:
    with _conn() as conn:
        return conn.execute(
            "SELECT * FROM check_log WHERE email = ? ORDER BY id DESC LIMIT ?",
            (email, limit),
        ).fetchall()


def get_all_check_log(limit: int = 500) -> list[sqlite3.Row]:
    with _conn() as conn:
        return conn.execute(
            "SELECT * FROM check_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()


def clear_check_log(email: str) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM check_log WHERE email = ?", (email,))
        conn.commit()


# ── Approvals ───────────────────────────────────────────────────────────────


def create_approval(
    email: str,
    approval_id: str,
    tool: str,
    params_json: str,
    rule_id: str | None,
    rule_name: str | None,
    subject_id: str | None,
) -> None:
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO approvals
              (id, email, tool, params_json, rule_id, rule_name, subject_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (approval_id, email, tool, params_json, rule_id, rule_name, subject_id, _now()),
        )
        conn.commit()


def get_approval(approval_id: str) -> sqlite3.Row | None:
    with _conn() as conn:
        return conn.execute(
            "SELECT * FROM approvals WHERE id = ?", (approval_id,)
        ).fetchone()


def resolve_approval(
    approval_id: str, verdict: str, reason: str | None
) -> sqlite3.Row | None:
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM approvals WHERE id = ? AND verdict IS NULL", (approval_id,)
        ).fetchone()
        if row is None:
            return None
        conn.execute(
            "UPDATE approvals SET verdict = ?, reason = ?, resolved_at = ? WHERE id = ?",
            (verdict, reason, _now(), approval_id),
        )
        conn.commit()
        return conn.execute(
            "SELECT * FROM approvals WHERE id = ?", (approval_id,)
        ).fetchone()


def list_approvals(email: str, pending_only: bool = False) -> list[sqlite3.Row]:
    with _conn() as conn:
        if pending_only:
            return conn.execute(
                """
                SELECT * FROM approvals
                WHERE email = ? AND verdict IS NULL
                ORDER BY created_at DESC
                """,
                (email,),
            ).fetchall()
        return conn.execute(
            "SELECT * FROM approvals WHERE email = ? ORDER BY created_at DESC LIMIT 200",
            (email,),
        ).fetchall()


def count_pending_approvals(email: str) -> int:
    with _conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM approvals WHERE email = ? AND verdict IS NULL",
            (email,),
        ).fetchone()
        return row[0] if row else 0
