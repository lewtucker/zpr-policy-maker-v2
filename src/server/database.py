"""Async SQLite storage for ZPR Policy Maker v2.

Tables:
  policy_sets   — PolicySet documents (Common IR, stored as JSON)
  conversations — Agent chat histories

All functions are coroutines; call init_db() once at startup.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

import aiosqlite

from ir_schema import Conversation, PolicySet

_DB_PATH = os.environ.get("DB_PATH", "zpr_policy.db")


async def init_db() -> None:
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS policy_sets (
                id         TEXT PRIMARY KEY,
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
                policy_set_id  TEXT,
                messages       TEXT NOT NULL DEFAULT '[]',
                created_at     TEXT NOT NULL,
                updated_at     TEXT NOT NULL
            )
        """)
        await db.commit()


# ── Policy sets ───────────────────────────────────────────────────────────────

async def save_policy_set(ps: PolicySet) -> PolicySet:
    ps.updated_at = datetime.now(timezone.utc)
    data = ps.model_dump_json()
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO policy_sets (id, name, language, data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name       = excluded.name,
                language   = excluded.language,
                data       = excluded.data,
                updated_at = excluded.updated_at
            """,
            (
                ps.id,
                ps.name,
                ps.language,
                data,
                ps.created_at.isoformat(),
                ps.updated_at.isoformat(),
            ),
        )
        await db.commit()
    return ps


async def get_policy_set(policy_set_id: str) -> PolicySet | None:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT data FROM policy_sets WHERE id = ?", (policy_set_id,)
        ) as cur:
            row = await cur.fetchone()
    if row is None:
        return None
    return PolicySet.model_validate_json(row["data"])


async def list_policy_sets() -> list[dict[str, Any]]:
    """Return lightweight summaries (no full data payload)."""
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, name, language, created_at, updated_at FROM policy_sets "
            "ORDER BY updated_at DESC"
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def delete_policy_set(policy_set_id: str) -> bool:
    async with aiosqlite.connect(_DB_PATH) as db:
        cur = await db.execute(
            "DELETE FROM policy_sets WHERE id = ?", (policy_set_id,)
        )
        await db.commit()
        return cur.rowcount > 0


# ── Conversations ─────────────────────────────────────────────────────────────

async def save_conversation(conv: Conversation) -> Conversation:
    conv.updated_at = datetime.now(timezone.utc)
    messages_json = json.dumps([m.model_dump() for m in conv.messages])
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO conversations (id, policy_set_id, messages, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                policy_set_id = excluded.policy_set_id,
                messages      = excluded.messages,
                updated_at    = excluded.updated_at
            """,
            (
                conv.id,
                conv.policy_set_id,
                messages_json,
                conv.created_at.isoformat(),
                conv.updated_at.isoformat(),
            ),
        )
        await db.commit()
    return conv


async def get_conversation(conv_id: str) -> Conversation | None:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM conversations WHERE id = ?", (conv_id,)
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


async def list_conversations() -> list[dict[str, Any]]:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, policy_set_id, created_at, updated_at FROM conversations "
            "ORDER BY updated_at DESC"
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]
