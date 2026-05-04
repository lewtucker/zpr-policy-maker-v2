"""Stage 5 regression tests: legacy /api/users/* gone; users table cleaned up."""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
import aiosqlite

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import database as db_module
from server import app
from test_helpers import make_session


@pytest_asyncio.fixture
async def lew_client(db, users):
    lew = users["lew"]
    root = await db.get_or_create_root_namespace(lew["id"], "Lew")
    cookie = make_session(lew["id"], "lew", "Lew", root["id"], "Lew")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        c.cookies.set("session", cookie)
        yield c, lew, root


# ── old endpoints removed ─────────────────────────────────────────────────────

async def test_get_users_serves_spa_not_json(db, lew_client):
    """GET /api/users no longer returns a user list — SPA catch-all serves HTML."""
    c, _, _ = lew_client
    resp = await c.get("/api/users")
    # Either a non-JSON response (HTML) or 404 is acceptable; must not return a list
    if resp.status_code == 200:
        assert "text/html" in resp.headers.get("content-type", "")
    else:
        assert resp.status_code in (404, 405)


async def test_post_users_gone(db, lew_client):
    c, _, _ = lew_client
    resp = await c.post("/api/users", json={"namespace_name": "Corp"})
    assert resp.status_code in (404, 405)


async def test_get_users_tree_serves_spa_not_json(db, lew_client):
    """GET /api/users/tree no longer returns owner tree — SPA catch-all serves HTML."""
    c, _, _ = lew_client
    resp = await c.get("/api/users/tree")
    if resp.status_code == 200:
        assert "text/html" in resp.headers.get("content-type", "")
    else:
        assert resp.status_code in (404, 405)


async def test_patch_users_id_gone(db, lew_client):
    c, _, _ = lew_client
    resp = await c.patch("/api/users/some-id", json={"display_name": "X"})
    assert resp.status_code in (404, 405)


async def test_delete_users_id_gone(db, lew_client):
    c, _, _ = lew_client
    resp = await c.delete("/api/users/some-id")
    assert resp.status_code in (404, 405)


# ── users table schema ────────────────────────────────────────────────────────

async def test_users_table_has_no_delegated_column(db):
    async with aiosqlite.connect(db_module._DB_PATH) as conn:
        async with conn.execute("PRAGMA table_info(users)") as cur:
            cols = {row[1] async for row in cur}
    assert "delegated" not in cols
    assert "delegated_to_user_id" not in cols
    assert "created_by_id" not in cols


async def test_users_table_has_expected_columns(db):
    async with aiosqlite.connect(db_module._DB_PATH) as conn:
        async with conn.execute("PRAGMA table_info(users)") as cur:
            cols = {row[1] async for row in cur}
    assert {"id", "username", "password_hash", "display_name", "email", "api_token", "created_at"} <= cols


# ── create_user no longer accepts legacy params ───────────────────────────────

async def test_create_user_no_delegated(db):
    user = await db.create_user("newuser", "password", display_name="New User")
    assert "delegated" not in user
    assert "created_by_id" not in user
    assert user["username"] == "newuser"
    assert user["display_name"] == "New User"


# ── profile & token endpoints still work ─────────────────────────────────────

async def test_get_profile(db, lew_client):
    c, lew, _ = lew_client
    resp = await c.get("/api/profile")
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "lew"
    assert "delegated" not in data
    assert "created_by_id" not in data


async def test_update_profile(db, lew_client):
    c, _, _ = lew_client
    resp = await c.post("/api/profile", json={"email": "lew@test.com"})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


async def test_regenerate_token(db, lew_client):
    c, _, _ = lew_client
    resp = await c.post("/api/token/regenerate")
    assert resp.status_code == 200
    assert "api_token" in resp.json()


async def test_change_password(db, lew_client):
    c, _, _ = lew_client
    resp = await c.post("/api/profile/password", json={
        "current_password": "password",
        "new_password": "newpass123",
    })
    assert resp.status_code == 200


# ── namespace endpoints still work ───────────────────────────────────────────

async def test_namespaces_tree_works(db, lew_client):
    c, _, root = lew_client
    resp = await c.get("/api/namespaces/tree")
    assert resp.status_code == 200
    assert resp.json()["id"] == root["id"]


async def test_create_namespace_works(db, lew_client):
    c, lew, _ = lew_client
    resp = await c.post("/api/namespaces", json={"display_name": "Corp"})
    assert resp.status_code == 201
    assert resp.json()["owner_user_id"] == lew["id"]


# ── delete_user respects root namespace block ─────────────────────────────────

async def test_delete_user_blocked_with_root_namespace(db, users):
    """Cannot delete a user who owns a root namespace."""
    lew_id = users["lew"]["id"]
    await db.get_or_create_root_namespace(lew_id, "Lew")
    err = await db.delete_user(lew_id)
    assert err is not None
    assert "root namespace" in err


async def test_delete_user_reassigns_child_namespaces(db, users):
    """Deleting a user who owns only child namespaces reassigns them."""
    lew_id   = users["lew"]["id"]
    alice_id = users["alice"]["id"]
    root  = await db.get_or_create_root_namespace(lew_id, "Lew")
    it    = await db.create_namespace("IT", alice_id, root["id"])

    err = await db.delete_user(alice_id)
    assert err is None
    reassigned = await db.get_namespace(it["id"])
    assert reassigned["owner_user_id"] == lew_id
