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

# ── Root namespace config defaults ────────────────────────────────────────────

DEFAULT_BUILTIN_CLASSES: list[str] = [
    "user", "users", "endpoint", "endpoints",
    "service", "services", "server", "servers",
]
DEFAULT_BUILTIN_ALIASES: dict[str, str] = {
    "user": "users", "users": "users",
    "endpoint": "endpoints", "endpoints": "endpoints",
    "service": "services", "services": "services",
    "server": "servers", "servers": "servers",
}
DEFAULT_BUILTIN_VERBS: list[str] = ["access", "use", "call", "read", "write"]


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
                id            TEXT PRIMARY KEY,
                username      TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name  TEXT NOT NULL DEFAULT '',
                email         TEXT NOT NULL DEFAULT '',
                api_token     TEXT,
                created_at    TEXT NOT NULL
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
                namespace_id TEXT PRIMARY KEY,
                zpl_text     TEXT NOT NULL DEFAULT '',
                updated_at   TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS namespaces (
                id                  TEXT PRIMARY KEY,
                display_name        TEXT NOT NULL,
                owner_user_id       TEXT NOT NULL,
                parent_namespace_id TEXT,
                created_at          TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS prompts (
                key        TEXT PRIMARY KEY,
                content    TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS namespace_entities (
                id           TEXT PRIMARY KEY,
                namespace_id TEXT NOT NULL,
                class_name   TEXT NOT NULL,
                name         TEXT NOT NULL,
                attributes   TEXT NOT NULL DEFAULT '{}',
                created_at   TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id             TEXT PRIMARY KEY,
                user_id        TEXT NOT NULL,
                namespace_id   TEXT NOT NULL,
                namespace_name TEXT NOT NULL,
                mode           TEXT NOT NULL DEFAULT 'fast',
                result_json    TEXT NOT NULL,
                title          TEXT NOT NULL,
                created_at     TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS root_namespace_config (
                root_namespace_id TEXT PRIMARY KEY,
                builtin_classes   TEXT NOT NULL,
                builtin_aliases   TEXT NOT NULL,
                builtin_verbs     TEXT NOT NULL
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
        if not await _column_exists(db, "users", "is_admin"):
            await db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
            # First user ever created becomes admin
            await db.execute(
                "UPDATE users SET is_admin = 1 WHERE id = (SELECT id FROM users ORDER BY created_at LIMIT 1)"
            )
        # Drop legacy columns (SQLite 3.35+)
        for _col in ("delegated", "delegated_to_user_id", "created_by_id"):
            if await _column_exists(db, "users", _col):
                await db.execute(f"ALTER TABLE users DROP COLUMN {_col}")
        # Migrate namespace_zpl: user_id → namespace_id
        if await _column_exists(db, "namespace_zpl", "user_id"):
            await db.execute("""
                CREATE TABLE namespace_zpl_new (
                    namespace_id TEXT PRIMARY KEY,
                    zpl_text     TEXT NOT NULL DEFAULT '',
                    updated_at   TEXT NOT NULL
                )
            """)
            await db.execute(
                "INSERT INTO namespace_zpl_new SELECT user_id, zpl_text, updated_at FROM namespace_zpl"
            )
            await db.execute("DROP TABLE namespace_zpl")
            await db.execute("ALTER TABLE namespace_zpl_new RENAME TO namespace_zpl")
        if not await _column_exists(db, "namespaces", "description"):
            await db.execute("ALTER TABLE namespaces ADD COLUMN description TEXT NOT NULL DEFAULT ''")
        if not await _column_exists(db, "namespaces", "created_by_user_id"):
            await db.execute("ALTER TABLE namespaces ADD COLUMN created_by_user_id TEXT")
            # Backfill: treat current owner as creator for existing rows
            await db.execute("UPDATE namespaces SET created_by_user_id = owner_user_id WHERE created_by_user_id IS NULL")
        if not await _column_exists(db, "users", "last_active"):
            await db.execute("ALTER TABLE users ADD COLUMN last_active TEXT")
            # Backfill from namespace_zpl updated_at for existing users
            await db.execute("""
                UPDATE users SET last_active = (
                    SELECT MAX(nz.updated_at)
                    FROM namespaces ns
                    JOIN namespace_zpl nz ON nz.namespace_id = ns.id
                    WHERE ns.owner_user_id = users.id
                )
            """)
        await db.commit()


# ── Users ─────────────────────────────────────────────────────────────────────

async def user_count() -> int:
    async with aiosqlite.connect(_DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM users") as cur:
            row = await cur.fetchone()
    return row[0] if row else 0


async def create_user(username: str, password: str, display_name: str | None = None,
                      email: str = "", is_admin: bool = False) -> dict:
    import uuid
    uid = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    dn = display_name or username
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            "INSERT INTO users (id, username, password_hash, display_name, email, is_admin, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (uid, username, hash_password(password), dn, email or "", int(is_admin), now),
        )
        await db.commit()
    return {"id": uid, "username": username, "display_name": dn, "email": email or "",
            "is_admin": is_admin, "created_at": now}


async def update_profile(user_id: str, email: str, display_name: str | None = None) -> None:
    async with aiosqlite.connect(_DB_PATH) as db:
        if display_name is not None:
            await db.execute(
                "UPDATE users SET email = ?, display_name = ? WHERE id = ?",
                (email, display_name, user_id),
            )
        else:
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


async def set_token(user_id: str, token: str) -> None:
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute("UPDATE users SET api_token = ? WHERE id = ?", (token, user_id))
        await db.commit()


async def update_user(user_id: str, *, display_name: str | None = None,
                      username: str | None = None, password: str | None = None,
                      email: str | None = None) -> None:
    sets, vals = [], []
    if display_name is not None:
        sets.append("display_name = ?"); vals.append(display_name)
    if username is not None:
        sets.append("username = ?"); vals.append(username)
    if password is not None:
        sets.append("password_hash = ?"); vals.append(hash_password(password))
    if email is not None:
        sets.append("email = ?"); vals.append(email)
    if not sets:
        return
    vals.append(user_id)
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", vals)
        await db.commit()


async def delete_user(user_id: str) -> str | None:
    """Delete user. Blocks if user owns a root namespace (no ancestor to reassign to)."""
    root_ns = await get_root_namespace(user_id)
    if root_ns:
        return "Cannot delete: user owns a root namespace. Delete that namespace first."
    await reassign_orphaned_namespaces(user_id)
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await db.commit()
    return None


# ── Namespace ZPL ────────────────────────────────────────────────────────────

async def get_namespace_zpl(namespace_id: str) -> str:
    async with aiosqlite.connect(_DB_PATH) as db:
        async with db.execute(
            "SELECT zpl_text FROM namespace_zpl WHERE namespace_id = ?", (namespace_id,)
        ) as cur:
            row = await cur.fetchone()
    return row[0] if row else ""


async def get_namespace_zpl_batch(namespace_ids: list[str]) -> dict[str, str]:
    """Return {namespace_id: zpl_text} for all given IDs that have ZPL stored."""
    if not namespace_ids:
        return {}
    placeholders = ",".join("?" * len(namespace_ids))
    async with aiosqlite.connect(_DB_PATH) as db:
        async with db.execute(
            f"SELECT namespace_id, zpl_text FROM namespace_zpl WHERE namespace_id IN ({placeholders})",
            namespace_ids,
        ) as cur:
            rows = await cur.fetchall()
    return {row[0]: row[1] for row in rows}


async def save_namespace_zpl(namespace_id: str, text: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            """INSERT INTO namespace_zpl (namespace_id, zpl_text, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(namespace_id) DO UPDATE SET
                   zpl_text = excluded.zpl_text,
                   updated_at = excluded.updated_at""",
            (namespace_id, text, now),
        )
        await db.commit()


async def list_all_namespace_zpl() -> list[tuple[str, str]]:
    """Return (namespace_id, zpl_text) for all namespaces — for simulation."""
    async with aiosqlite.connect(_DB_PATH) as db:
        async with db.execute("SELECT namespace_id, zpl_text FROM namespace_zpl") as cur:
            rows = await cur.fetchall()
    return [(r[0], r[1]) for r in rows]


# ── Prompts ───────────────────────────────────────────────────────────────────

async def get_prompt(key: str) -> str | None:
    async with aiosqlite.connect(_DB_PATH) as db:
        async with db.execute("SELECT content FROM prompts WHERE key = ?", (key,)) as cur:
            row = await cur.fetchone()
    return row[0] if row else None


async def save_prompt(key: str, content: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            """INSERT INTO prompts (key, content, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET
                   content = excluded.content,
                   updated_at = excluded.updated_at""",
            (key, content, now),
        )
        await db.commit()


# ── Namespaces ────────────────────────────────────────────────────────────────

async def create_namespace(display_name: str, owner_user_id: str,
                           parent_namespace_id: str | None = None,
                           description: str = "",
                           created_by_user_id: str | None = None) -> dict:
    import uuid as _uuid
    ns_id = _uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    creator = created_by_user_id or owner_user_id
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            "INSERT INTO namespaces (id, display_name, owner_user_id, parent_namespace_id, created_at, description, created_by_user_id) "
            "VALUES (?,?,?,?,?,?,?)",
            (ns_id, display_name, owner_user_id, parent_namespace_id, now, description or "", creator),
        )
        await db.commit()
    return {"id": ns_id, "display_name": display_name, "owner_user_id": owner_user_id,
            "parent_namespace_id": parent_namespace_id, "created_at": now,
            "description": description or "", "created_by_user_id": creator}


async def get_namespace(namespace_id: str) -> dict | None:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM namespaces WHERE id = ?", (namespace_id,)
        ) as cur:
            row = await cur.fetchone()
    return dict(row) if row else None


async def update_namespace(namespace_id: str, *, display_name: str | None = None,
                           owner_user_id: str | None = None,
                           description: str | None = None) -> None:
    sets, vals = [], []
    if display_name is not None:
        sets.append("display_name = ?"); vals.append(display_name)
    if owner_user_id is not None:
        sets.append("owner_user_id = ?"); vals.append(owner_user_id)
    if description is not None:
        sets.append("description = ?"); vals.append(description)
    if not sets:
        return
    vals.append(namespace_id)
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(f"UPDATE namespaces SET {', '.join(sets)} WHERE id = ?", vals)
        await db.commit()


async def delete_namespace(namespace_id: str) -> str | None:
    """Delete namespace. Returns error string if it has children."""
    async with aiosqlite.connect(_DB_PATH) as db:
        async with db.execute(
            "SELECT COUNT(*) FROM namespaces WHERE parent_namespace_id = ?", (namespace_id,)
        ) as cur:
            row = await cur.fetchone()
        if row and row[0] > 0:
            return "Cannot delete: namespace has children. Delete those first."
        await db.execute("DELETE FROM namespaces WHERE id = ?", (namespace_id,))
        await db.execute("DELETE FROM namespace_zpl WHERE namespace_id = ?", (namespace_id,))
        await db.commit()
    return None


async def delete_namespace_cascade(namespace_id: str) -> None:
    """Delete a namespace and all its descendants (leaves first)."""
    async with aiosqlite.connect(_DB_PATH) as db:
        async with db.execute(
            """WITH RECURSIVE sub(id) AS (
                   SELECT ? UNION ALL
                   SELECT n.id FROM namespaces n JOIN sub s ON n.parent_namespace_id = s.id
               ) SELECT id FROM sub""",
            (namespace_id,),
        ) as cur:
            ids = [row[0] for row in await cur.fetchall()]
        # Delete in reverse order so children go before parents
        for ns_id in reversed(ids):
            await db.execute("DELETE FROM namespace_zpl WHERE namespace_id = ?", (ns_id,))
            await db.execute("DELETE FROM namespaces WHERE id = ?", (ns_id,))
        await db.commit()


async def get_namespace_tree(root_id: str) -> dict:
    """Return full namespace tree rooted at root_id as nested dicts."""
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT n.id, n.display_name, n.owner_user_id, n.parent_namespace_id, n.created_at, "
            "COALESCE(n.description, '') AS description, "
            "u.username AS owner_username, "
            "COALESCE(n.created_by_user_id, n.owner_user_id) AS created_by_user_id, "
            "cb.username AS created_by_username "
            "FROM namespaces n "
            "LEFT JOIN users u ON u.id = n.owner_user_id "
            "LEFT JOIN users cb ON cb.id = n.created_by_user_id"
        ) as cur:
            all_rows = [dict(r) for r in await cur.fetchall()]
    by_id = {r["id"]: {**r, "children": []} for r in all_rows}
    for r in all_rows:
        pid = r["parent_namespace_id"]
        if pid and pid in by_id:
            by_id[pid]["children"].append(by_id[r["id"]])
    return by_id.get(root_id, {})


async def touch_last_active(user_id: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute("UPDATE users SET last_active = ? WHERE id = ?", (now, user_id))
        await db.commit()


async def list_all_users() -> list[dict]:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, username, display_name, email, api_token, is_admin, created_at, last_active FROM users ORDER BY created_at"
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def set_user_admin(user_id: str, is_admin: bool) -> None:
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute("UPDATE users SET is_admin = ? WHERE id = ?", (int(is_admin), user_id))
        await db.commit()


async def list_all_namespaces() -> list[dict]:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT n.id, n.display_name, n.parent_namespace_id, n.created_at, "
            "u.username AS owner_username, u.display_name AS owner_display_name "
            "FROM namespaces n LEFT JOIN users u ON u.id = n.owner_user_id "
            "ORDER BY n.display_name"
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def get_root_namespace(user_id: str) -> dict | None:
    """Return the root namespace (no parent) owned by user_id, or None."""
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM namespaces WHERE owner_user_id = ? AND parent_namespace_id IS NULL LIMIT 1",
            (user_id,)
        ) as cur:
            row = await cur.fetchone()
    return dict(row) if row else None


async def get_or_create_root_namespace(user_id: str, display_name: str) -> dict:
    """Return the root namespace for user_id, creating it if necessary."""
    existing = await get_root_namespace(user_id)
    if existing:
        return existing
    return await create_namespace(display_name, user_id, parent_namespace_id=None)


async def get_namespaces_owned_by(user_id: str) -> list[dict]:
    """All namespaces where owner_user_id = user_id, ordered by display_name."""
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM namespaces WHERE owner_user_id = ? ORDER BY display_name",
            (user_id,)
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def can_access_namespace(user_id: str, namespace_id: str) -> bool:
    """True if user owns this namespace or any ancestor namespace."""
    async with aiosqlite.connect(_DB_PATH) as db:
        current_id: str | None = namespace_id
        seen: set[str] = set()
        while current_id and current_id not in seen:
            seen.add(current_id)
            async with db.execute(
                "SELECT owner_user_id, parent_namespace_id FROM namespaces WHERE id = ?",
                (current_id,)
            ) as cur:
                row = await cur.fetchone()
            if row is None:
                break
            if row[0] == user_id:
                return True
            current_id = row[1]
    return False


async def reassign_orphaned_namespaces(deleted_user_id: str) -> None:
    """Reassign namespaces owned by deleted_user_id to nearest active ancestor owner."""
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, parent_namespace_id FROM namespaces WHERE owner_user_id = ?",
            (deleted_user_id,)
        ) as cur:
            owned = [dict(r) for r in await cur.fetchall()]
        for ns in owned:
            current_id: str | None = ns["parent_namespace_id"]
            seen: set[str] = set()
            new_owner: str | None = None
            while current_id and current_id not in seen:
                seen.add(current_id)
                async with db.execute(
                    "SELECT owner_user_id, parent_namespace_id FROM namespaces WHERE id = ?",
                    (current_id,)
                ) as cur2:
                    row = await cur2.fetchone()
                if row is None:
                    break
                if row[0] != deleted_user_id:
                    new_owner = row[0]
                    break
                current_id = row[1]
            if new_owner:
                await db.execute(
                    "UPDATE namespaces SET owner_user_id = ? WHERE id = ?",
                    (new_owner, ns["id"]),
                )
        await db.commit()


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


# ── Entities ──────────────────────────────────────────────────────────────────

async def get_entities(namespace_id: str) -> list[dict]:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM namespace_entities WHERE namespace_id = ? ORDER BY class_name, name",
            (namespace_id,)
        ) as cur:
            rows = await cur.fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["attributes"] = json.loads(d["attributes"])
        result.append(d)
    return result


async def create_entity(namespace_id: str, class_name: str, name: str,
                        attributes: dict) -> dict:
    import uuid as _uuid
    eid = _uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            "INSERT INTO namespace_entities (id, namespace_id, class_name, name, attributes, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (eid, namespace_id, class_name, name, json.dumps(attributes), now),
        )
        await db.commit()
    return {"id": eid, "namespace_id": namespace_id, "class_name": class_name,
            "name": name, "attributes": attributes, "created_at": now}


async def update_entity(entity_id: str, namespace_id: str, *, class_name: str | None = None,
                        name: str | None = None, attributes: dict | None = None) -> bool:
    sets, vals = [], []
    if class_name is not None:
        sets.append("class_name = ?"); vals.append(class_name)
    if name is not None:
        sets.append("name = ?"); vals.append(name)
    if attributes is not None:
        sets.append("attributes = ?"); vals.append(json.dumps(attributes))
    if not sets:
        return True
    vals.extend([entity_id, namespace_id])
    async with aiosqlite.connect(_DB_PATH) as db:
        cur = await db.execute(
            f"UPDATE namespace_entities SET {', '.join(sets)} WHERE id = ? AND namespace_id = ?",
            vals
        )
        await db.commit()
        return cur.rowcount > 0


async def delete_entity(entity_id: str, namespace_id: str) -> bool:
    async with aiosqlite.connect(_DB_PATH) as db:
        cur = await db.execute(
            "DELETE FROM namespace_entities WHERE id = ? AND namespace_id = ?",
            (entity_id, namespace_id)
        )
        await db.commit()
        return cur.rowcount > 0


async def delete_all_entities(namespace_id: str) -> int:
    async with aiosqlite.connect(_DB_PATH) as db:
        cur = await db.execute(
            "DELETE FROM namespace_entities WHERE namespace_id = ?", (namespace_id,)
        )
        await db.commit()
        return cur.rowcount


# ── Reports ───────────────────────────────────────────────────────────────────

async def count_reports_for_ns(user_id: str, namespace_id: str) -> int:
    async with aiosqlite.connect(_DB_PATH) as db:
        async with db.execute(
            "SELECT COUNT(*) FROM reports WHERE user_id = ? AND namespace_id = ?",
            (user_id, namespace_id),
        ) as cur:
            row = await cur.fetchone()
    return row[0] if row else 0


async def save_report(user_id: str, namespace_id: str, namespace_name: str,
                      mode: str, result: dict, title: str) -> dict:
    import uuid as _uuid
    rid = _uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            "INSERT INTO reports (id, user_id, namespace_id, namespace_name, mode, result_json, title, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (rid, user_id, namespace_id, namespace_name, mode, json.dumps(result), title, now),
        )
        await db.commit()
    return {"id": rid, "user_id": user_id, "namespace_id": namespace_id,
            "namespace_name": namespace_name, "mode": mode, "result": result,
            "title": title, "created_at": now}


async def list_reports(user_id: str) -> list[dict]:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, namespace_id, namespace_name, mode, title, created_at "
            "FROM reports WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def get_report(report_id: str, user_id: str) -> dict | None:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, namespace_id, namespace_name, mode, result_json, title, created_at "
            "FROM reports WHERE id = ? AND user_id = ?",
            (report_id, user_id),
        ) as cur:
            row = await cur.fetchone()
    if not row:
        return None
    d = dict(row)
    d["result"] = json.loads(d.pop("result_json"))
    return d


async def delete_report(report_id: str, user_id: str) -> bool:
    async with aiosqlite.connect(_DB_PATH) as db:
        cur = await db.execute(
            "DELETE FROM reports WHERE id = ? AND user_id = ?", (report_id, user_id)
        )
        await db.commit()
        return cur.rowcount > 0


# ── Root namespace config ─────────────────────────────────────────────────────

async def get_root_config(root_namespace_id: str) -> dict:
    """Return the builtin config for a root namespace, falling back to defaults."""
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT builtin_classes, builtin_aliases, builtin_verbs FROM root_namespace_config WHERE root_namespace_id = ?",
            (root_namespace_id,),
        ) as cur:
            row = await cur.fetchone()
    if not row:
        return {
            "builtin_classes": DEFAULT_BUILTIN_CLASSES,
            "builtin_aliases": DEFAULT_BUILTIN_ALIASES,
            "builtin_verbs": DEFAULT_BUILTIN_VERBS,
        }
    return {
        "builtin_classes": json.loads(row["builtin_classes"]),
        "builtin_aliases": json.loads(row["builtin_aliases"]),
        "builtin_verbs": json.loads(row["builtin_verbs"]),
    }


async def save_root_config(
    root_namespace_id: str,
    builtin_classes: list[str],
    builtin_aliases: dict[str, str],
    builtin_verbs: list[str],
) -> None:
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            """INSERT INTO root_namespace_config (root_namespace_id, builtin_classes, builtin_aliases, builtin_verbs)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(root_namespace_id) DO UPDATE SET
                 builtin_classes = excluded.builtin_classes,
                 builtin_aliases = excluded.builtin_aliases,
                 builtin_verbs   = excluded.builtin_verbs""",
            (
                root_namespace_id,
                json.dumps(builtin_classes),
                json.dumps(builtin_aliases),
                json.dumps(builtin_verbs),
            ),
        )
        await db.commit()
