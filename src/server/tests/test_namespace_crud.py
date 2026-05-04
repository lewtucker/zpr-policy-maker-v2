"""Stage 3 tests: namespace CRUD HTTP endpoints."""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import database as db_module
from server import app
from test_helpers import make_session as _session


@pytest_asyncio.fixture
async def lew_client(db, users):
    lew = users["lew"]
    root = await db.get_or_create_root_namespace(lew["id"], "Lew")
    cookie = _session(lew["id"], "lew", "Lew", root["id"], "Lew")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        c.cookies.set("session", cookie)
        yield c, lew, root


@pytest_asyncio.fixture
async def alice_client(db, users):
    alice = users["alice"]
    root = await db.get_or_create_root_namespace(alice["id"], "Alice")
    cookie = _session(alice["id"], "alice", "Alice", root["id"], "Alice")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        c.cookies.set("session", cookie)
        yield c, alice, root


# ── GET /api/namespaces/tree ──────────────────────────────────────────────────

async def test_tree_returns_root(db, lew_client):
    c, lew, root = lew_client
    resp = await c.get("/api/namespaces/tree")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == root["id"]
    assert data["display_name"] == "Lew"
    assert data["children"] == []


async def test_tree_includes_children(db, lew_client):
    c, lew, root = lew_client
    await db.create_namespace("Corp", lew["id"], root["id"])
    resp = await c.get("/api/namespaces/tree")
    assert resp.status_code == 200
    names = {n["display_name"] for n in resp.json()["children"]}
    assert "Corp" in names


async def test_tree_no_root_returns_empty(db, users):
    bob = users["bob"]
    cookie = _session(bob["id"], "bob", "Bob", "fake-ns-id", "Bob")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        c.cookies.set("session", cookie)
        resp = await c.get("/api/namespaces/tree")
    assert resp.status_code == 200
    assert resp.json() == {}


# ── POST /api/namespaces ──────────────────────────────────────────────────────

async def test_create_defaults_to_login_user_owner(db, lew_client):
    c, lew, root = lew_client
    resp = await c.post("/api/namespaces", json={"display_name": "Corp"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["display_name"] == "Corp"
    assert data["owner_user_id"] == lew["id"]
    assert data["parent_namespace_id"] == root["id"]


async def test_create_under_explicit_parent(db, lew_client):
    c, lew, root = lew_client
    corp = await db.create_namespace("Corp", lew["id"], root["id"])
    resp = await c.post("/api/namespaces", json={"display_name": "IT", "parent_id": corp["id"]})
    assert resp.status_code == 201
    assert resp.json()["parent_namespace_id"] == corp["id"]


async def test_create_assigns_existing_user_as_owner(db, lew_client, users):
    c, lew, root = lew_client
    resp = await c.post("/api/namespaces", json={
        "display_name": "Corp",
        "owner_user_id": users["alice"]["id"],
    })
    assert resp.status_code == 201
    assert resp.json()["owner_user_id"] == users["alice"]["id"]


async def test_create_new_user_as_owner(db, lew_client):
    c, lew, root = lew_client
    resp = await c.post("/api/namespaces", json={
        "display_name": "Corp",
        "owner_username": "newperson",
        "owner_password": "secret123",
    })
    assert resp.status_code == 201
    new_user = await db.get_user_by_username("newperson")
    assert new_user is not None
    assert resp.json()["owner_user_id"] == new_user["id"]


async def test_create_owner_username_reuses_existing(db, lew_client, users):
    """If owner_username matches existing user, assign them — don't create a duplicate."""
    c, lew, root = lew_client
    resp = await c.post("/api/namespaces", json={
        "display_name": "Corp",
        "owner_username": "alice",
    })
    assert resp.status_code == 201
    assert resp.json()["owner_user_id"] == users["alice"]["id"]


async def test_create_unknown_owner_username_without_password_is_400(db, lew_client):
    c, _, _ = lew_client
    resp = await c.post("/api/namespaces", json={
        "display_name": "Corp",
        "owner_username": "ghost",
    })
    assert resp.status_code == 400


async def test_create_blocked_under_foreign_namespace(db, alice_client, users):
    c, alice, _ = alice_client
    lew_root = await db.get_or_create_root_namespace(users["lew"]["id"], "Lew")
    resp = await c.post("/api/namespaces", json={
        "display_name": "Hack",
        "parent_id": lew_root["id"],
    })
    assert resp.status_code == 403


async def test_create_empty_display_name_is_400(db, lew_client):
    c, _, _ = lew_client
    resp = await c.post("/api/namespaces", json={"display_name": "   "})
    assert resp.status_code == 400


# ── PATCH /api/namespaces/{id} ────────────────────────────────────────────────

async def test_patch_display_name(db, lew_client):
    c, lew, root = lew_client
    ns = await db.create_namespace("Corp", lew["id"], root["id"])
    resp = await c.patch(f"/api/namespaces/{ns['id']}", json={"display_name": "Acme"})
    assert resp.status_code == 200
    updated = await db.get_namespace(ns["id"])
    assert updated["display_name"] == "Acme"


async def test_patch_owner(db, lew_client, users):
    c, lew, root = lew_client
    ns = await db.create_namespace("Corp", lew["id"], root["id"])
    resp = await c.patch(f"/api/namespaces/{ns['id']}", json={"owner_user_id": users["alice"]["id"]})
    assert resp.status_code == 200
    assert (await db.get_namespace(ns["id"]))["owner_user_id"] == users["alice"]["id"]


async def test_patch_noop(db, lew_client):
    c, lew, root = lew_client
    ns = await db.create_namespace("Corp", lew["id"], root["id"])
    resp = await c.patch(f"/api/namespaces/{ns['id']}", json={})
    assert resp.status_code == 200
    assert (await db.get_namespace(ns["id"]))["display_name"] == "Corp"


async def test_patch_blocked_for_foreign(db, alice_client, users):
    c, alice, _ = alice_client
    lew_root = await db.get_or_create_root_namespace(users["lew"]["id"], "Lew")
    ns = await db.create_namespace("Corp", users["lew"]["id"], lew_root["id"])
    resp = await c.patch(f"/api/namespaces/{ns['id']}", json={"display_name": "Hack"})
    assert resp.status_code == 403


async def test_patch_nonexistent_is_404(db, lew_client):
    c, _, _ = lew_client
    resp = await c.patch("/api/namespaces/no-such-id", json={"display_name": "X"})
    assert resp.status_code in (403, 404)


# ── DELETE /api/namespaces/{id} ───────────────────────────────────────────────

async def test_delete_leaf(db, lew_client):
    c, lew, root = lew_client
    ns = await db.create_namespace("Corp", lew["id"], root["id"])
    resp = await c.delete(f"/api/namespaces/{ns['id']}")
    assert resp.status_code == 204
    assert await db.get_namespace(ns["id"]) is None


async def test_delete_blocked_if_has_children(db, lew_client):
    c, lew, root = lew_client
    corp = await db.create_namespace("Corp", lew["id"], root["id"])
    await db.create_namespace("IT", lew["id"], corp["id"])
    resp = await c.delete(f"/api/namespaces/{corp['id']}")
    assert resp.status_code == 409


async def test_delete_root_blocked(db, lew_client):
    c, _, root = lew_client
    resp = await c.delete(f"/api/namespaces/{root['id']}")
    assert resp.status_code == 400


async def test_delete_blocked_for_foreign(db, alice_client, users):
    c, alice, _ = alice_client
    lew_root = await db.get_or_create_root_namespace(users["lew"]["id"], "Lew")
    ns = await db.create_namespace("Corp", users["lew"]["id"], lew_root["id"])
    resp = await c.delete(f"/api/namespaces/{ns['id']}")
    assert resp.status_code == 403
