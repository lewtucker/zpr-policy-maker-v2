"""Async SQLite storage for ZPR Policy Maker v2.

Tables:
  users         — owner accounts (username = namespace name)
  policy_sets   — PolicySet documents scoped to a user
  conversations — Agent chat histories scoped to a user

All functions are coroutines; call init_db() once at startup.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from typing import Any

import aiosqlite

from ir_schema import Conversation, PolicySet

_DB_PATH = os.environ.get("DB_PATH", "zpr_policy.db")


# ── Password hashing (pbkdf2, no extra deps) ──────────────────────────────────

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"{salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, dk_hex = stored.split("$", 1)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return secrets.compare_digest(dk.hex(), dk_hex)


# ── Schema ────────────────────────────────────────────────────────────────────

async def _column_exists(db, table: str, column: str) -> bool:
    async with db.execute(f"PRAGMA table_info({table})") as cur:
        rows = await cur.fetchall()
    return any(row[1] == column for row in rows)


async def init_db() -> None:
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id               TEXT PRIMARY KEY,
                username         TEXT NOT NULL UNIQUE,
                password_hash    TEXT NOT NULL,
                display_name     TEXT NOT NULL DEFAULT '',
                created_by_id    TEXT,
                created_at       TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS policy_sets (
                id         TEXT PRIMARY KEY,
                user_id    TEXT NOT NULL DEFAULT 'legacy',
                name       TEXT NOT NULL,
                language   TEXT NOT NULL DEFAULT 'zpl',
                data       TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS conversations (
                id             TEXT PRIMARY KEY,
                user_id        TEXT NOT NULL DEFAULT 'legacy',
                policy_set_id  TEXT,
                messages       TEXT NOT NULL DEFAULT '[]',
                created_at     TEXT NOT NULL,
                updated_at     TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS namespace_zpl (
                user_id    TEXT PRIMARY KEY,
                zpl_text   TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            )
        """)
        # Migrations for older schemas
        if not await _column_exists(db, "policy_sets", "user_id"):
            await db.execute("ALTER TABLE policy_sets ADD COLUMN user_id TEXT NOT NULL DEFAULT 'legacy'")
        if not await _column_exists(db, "conversations", "user_id"):
            await db.execute("ALTER TABLE conversations ADD COLUMN user_id TEXT NOT NULL DEFAULT 'legacy'")
        if not await _column_exists(db, "users", "display_name"):
            await db.execute("ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''")
            await db.execute("UPDATE users SET display_name = username WHERE display_name = ''")
        if not await _column_exists(db, "users", "api_token"):
            await db.execute("ALTER TABLE users ADD COLUMN api_token TEXT")
        if not await _column_exists(db, "users", "email"):
            await db.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")
        if not await _column_exists(db, "users", "delegated"):
            await db.execute("ALTER TABLE users ADD COLUMN delegated INTEGER NOT NULL DEFAULT 0")
        if not await _column_exists(db, "users", "delegated_to_user_id"):
            await db.execute("ALTER TABLE users ADD COLUMN delegated_to_user_id TEXT")
        await db.commit()


# ── Users ─────────────────────────────────────────────────────────────────────

async def user_count() -> int:
    async with aiosqlite.connect(_DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM users") as cur:
            row = await cur.fetchone()
    return row[0] if row else 0


async def create_user(username: str, password: str, display_name: str | None = None,
                      created_by_id: str | None = None, email: str = "",
                      delegated: bool = False) -> dict:
    import uuid
    uid = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    dn = display_name or username
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            "INSERT INTO users (id, username, password_hash, display_name, email, delegated, created_by_id, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (uid, username, hash_password(password), dn, email or "", int(delegated), created_by_id, now),
        )
        await db.commit()
    return {"id": uid, "username": username, "display_name": dn, "email": email or "",
            "delegated": delegated, "created_by_id": created_by_id, "created_at": now}


async def update_profile(user_id: str, email: str) -> None:
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute("UPDATE users SET email = ? WHERE id = ?", (email, user_id))
        await db.commit()


async def get_user_by_username(username: str) -> dict | None:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ) as cur:
            row = await cur.fetchone()
    return dict(row) if row else None


async def get_user_by_id(user_id: str) -> dict | None:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ) as cur:
            row = await cur.fetchone()
    return dict(row) if row else None


async def update_password(user_id: str, new_password: str) -> None:
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(new_password), user_id),
        )
        await db.commit()


async def get_user_by_token(token: str) -> dict | None:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM users WHERE api_token = ?", (token,)
        ) as cur:
            row = await cur.fetchone()
    return dict(row) if row else None


async def regenerate_token(user_id: str) -> str:
    import secrets
    token = secrets.token_urlsafe(32)
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute("UPDATE users SET api_token = ? WHERE id = ?", (token, user_id))
        await db.commit()
    return token


async def update_user(user_id: str, *, display_name: str | None = None,
                      username: str | None = None, password: str | None = None,
                      email: str | None = None, delegated: bool | None = None,
                      delegated_to_user_id: str | None = None) -> None:
    sets, vals = [], []
    if display_name is not None:
        sets.append("display_name = ?"); vals.append(display_name)
    if username is not None:
        sets.append("username = ?"); vals.append(username)
    if password is not None:
        sets.append("password_hash = ?"); vals.append(hash_password(password))
    if email is not None:
        sets.append("email = ?"); vals.append(email)
    if delegated is not None:
        sets.append("delegated = ?"); vals.append(int(delegated))
    if delegated_to_user_id is not None:
        sets.append("delegated_to_user_id = ?"); vals.append(delegated_to_user_id)
    if not sets:
        return
    vals.append(user_id)
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", vals)
        await db.commit()


async def delete_user(user_id: str) -> str | None:
    """Delete user. Returns error string if the user has children, else None."""
    async with aiosqlite.connect(_DB_PATH) as db:
        async with db.execute(
            "SELECT COUNT(*) FROM users WHERE created_by_id = ?", (user_id,)
        ) as cur:
            row = await cur.fetchone()
        if row and row[0] > 0:
            return "Cannot delete: this owner has sub-namespaces. Delete those first."
        await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await db.execute("DELETE FROM namespace_zpl WHERE user_id = ?", (user_id,))
        await db.commit()
    return None


async def list_users_created_by(creator_id: str) -> list[dict]:
    """Return all users directly created by creator_id."""
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, username, display_name, email, delegated, created_by_id, created_at FROM users "
            "WHERE created_by_id = ? ORDER BY display_name",
            (creator_id,),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def get_owner_tree(root_id: str) -> dict:
    """Return the full ownership tree rooted at root_id as nested dicts."""
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, username, display_name, email, delegated, delegated_to_user_id, "
            "created_by_id, created_at FROM users"
        ) as cur:
            all_rows = [dict(r) for r in await cur.fetchall()]

    by_id = {r["id"]: {**r, "children": []} for r in all_rows}

    # Resolve delegated_to_user info into each row
    for r in by_id.values():
        dtuid = r.get("delegated_to_user_id")
        if dtuid and dtuid in by_id:
            du = by_id[dtuid]
            r["owner_username"] = du["username"]
            r["owner_email"] = du["email"]
        elif r.get("delegated"):
            r["owner_username"] = r["username"]
            r["owner_email"] = r["email"]
        else:
            r["owner_username"] = None
            r["owner_email"] = None

    for r in all_rows:
        parent_id = r["created_by_id"]
        if parent_id and parent_id in by_id:
            by_id[parent_id]["children"].append(by_id[r["id"]])

    return by_id.get(root_id, {})


async def can_switch_to(login_user_id: str, target_user_id: str) -> bool:
    """Return True if login_user_id is an ancestor (direct or indirect) of target_user_id."""
    if login_user_id == target_user_id:
        return True
    async with aiosqlite.connect(_DB_PATH) as db:
        # Allow if login_user is the delegated owner of the target namespace
        async with db.execute(
            "SELECT delegated_to_user_id FROM users WHERE id = ?", (target_user_id,)
        ) as cur:
            row = await cur.fetchone()
        if row and row[0] == login_user_id:
            return True
        # Walk up the created_by chain from target
        current_id = target_user_id
        seen = set()
        while current_id and current_id not in seen:
            seen.add(current_id)
            async with db.execute(
                "SELECT created_by_id FROM users WHERE id = ?", (current_id,)
            ) as cur:
                row = await cur.fetchone()
            if row is None:
                break
            current_id = row[0]
            if current_id == login_user_id:
                return True
    return False


# ── Namespace ZPL ────────────────────────────────────────────────────────────

async def get_namespace_zpl(user_id: str) -> str:
    async with aiosqlite.connect(_DB_PATH) as db:
        async with db.execute(
            "SELECT zpl_text FROM namespace_zpl WHERE user_id = ?", (user_id,)
        ) as cur:
            row = await cur.fetchone()
    return row[0] if row else ""


async def save_namespace_zpl(user_id: str, text: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            """INSERT INTO namespace_zpl (user_id, zpl_text, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(user_id) DO UPDATE SET
                   zpl_text = excluded.zpl_text,
                   updated_at = excluded.updated_at""",
            (user_id, text, now),
        )
        await db.commit()


async def list_all_namespace_zpl() -> list[tuple[str, str]]:
    """Return (user_id, zpl_text) for all namespaces — for simulation."""
    async with aiosqlite.connect(_DB_PATH) as db:
        async with db.execute("SELECT user_id, zpl_text FROM namespace_zpl") as cur:
            rows = await cur.fetchall()
    return [(r[0], r[1]) for r in rows]


# ── Policy sets ───────────────────────────────────────────────────────────────

async def save_policy_set(ps: PolicySet, user_id: str) -> PolicySet:
    ps.updated_at = datetime.now(timezone.utc)
    data = ps.model_dump_json()
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO policy_sets (id, user_id, name, language, data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name       = excluded.name,
                language   = excluded.language,
                data       = excluded.data,
                updated_at = excluded.updated_at
            """,
            (ps.id, user_id, ps.name, ps.language, data,
             ps.created_at.isoformat(), ps.updated_at.isoformat()),
        )
        await db.commit()
    return ps


async def get_policy_set(policy_set_id: str, user_id: str) -> PolicySet | None:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT data FROM policy_sets WHERE id = ? AND user_id = ?",
            (policy_set_id, user_id),
        ) as cur:
            row = await cur.fetchone()
    if row is None:
        return None
    return PolicySet.model_validate_json(row["data"])


async def list_policy_sets(user_id: str) -> list[dict[str, Any]]:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, name, language, created_at, updated_at FROM policy_sets "
            "WHERE user_id = ? ORDER BY updated_at DESC",
            (user_id,),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def delete_policy_set(policy_set_id: str, user_id: str) -> bool:
    async with aiosqlite.connect(_DB_PATH) as db:
        cur = await db.execute(
            "DELETE FROM policy_sets WHERE id = ? AND user_id = ?",
            (policy_set_id, user_id),
        )
        await db.commit()
        return cur.rowcount > 0


async def list_all_policy_sets() -> list[PolicySet]:
    """Load every policy set across all users — used for simulation only."""
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT data FROM policy_sets") as cur:
            rows = await cur.fetchall()
    return [PolicySet.model_validate_json(r["data"]) for r in rows]


# ── Conversations ─────────────────────────────────────────────────────────────

async def save_conversation(conv: Conversation, user_id: str) -> Conversation:
    conv.updated_at = datetime.now(timezone.utc)
    messages_json = json.dumps([m.model_dump() for m in conv.messages])
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO conversations (id, user_id, policy_set_id, messages, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                policy_set_id = excluded.policy_set_id,
                messages      = excluded.messages,
                updated_at    = excluded.updated_at
            """,
            (conv.id, user_id, conv.policy_set_id, messages_json,
             conv.created_at.isoformat(), conv.updated_at.isoformat()),
        )
        await db.commit()
    return conv


async def get_conversation(conv_id: str, user_id: str) -> Conversation | None:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM conversations WHERE id = ? AND user_id = ?",
            (conv_id, user_id),
        ) as cur:
            row = await cur.fetchone()
    if row is None:
        return None
    from ir_schema import ChatMessage
    messages = [ChatMessage(**m) for m in json.loads(row["messages"])]
    return Conversation(
        id=row["id"],
        policy_set_id=row["policy_set_id"],
        messages=messages,
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )
