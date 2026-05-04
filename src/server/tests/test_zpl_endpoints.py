"""Stage 4 tests: ZPL endpoints keyed by namespace_id + rename re-prefix."""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import database as db_module
from server import app
from test_helpers import make_session


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def lew_setup(db, users):
    """Lew with root namespace; returns (client, user, root_ns)."""
    lew = users["lew"]
    root = await db.get_or_create_root_namespace(lew["id"], "Lew")
    cookie = make_session(lew["id"], "lew", "Lew", root["id"], "Lew")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        c.cookies.set("session", cookie)
        yield c, lew, root


@pytest_asyncio.fixture
async def corp_setup(db, users):
    """Lew root → Corp namespace; returns (client, lew, corp_ns)."""
    lew = users["lew"]
    root = await db.get_or_create_root_namespace(lew["id"], "Lew")
    corp = await db.create_namespace("Corp", lew["id"], root["id"])
    cookie = make_session(lew["id"], "lew", "Lew", corp["id"], "Corp")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        c.cookies.set("session", cookie)
        yield c, lew, root, corp


# ── namespace_id keying ───────────────────────────────────────────────────────

async def test_save_and_retrieve_zpl(db, lew_setup):
    c, lew, root = lew_setup
    zpl = "Allow employees to access services."
    resp = await c.put("/api/namespace/zpl", json={"text": zpl})
    assert resp.status_code == 200

    resp = await c.get("/api/namespace/zpl")
    assert resp.status_code == 200
    assert "Allow" in resp.json()["text"]


async def test_zpl_stored_with_namespace_prefix(db, lew_setup):
    """ZPL saved under active namespace stores with that namespace's display_name prefix."""
    c, lew, root = lew_setup
    zpl = "Define Employee as a users."
    await c.put("/api/namespace/zpl", json={"text": zpl})
    stored = await db.get_namespace_zpl(root["id"])
    assert "Lew.Employee" in stored


async def test_get_returns_stripped_zpl(db, lew_setup):
    """GET /api/namespace/zpl strips the active namespace prefix before returning."""
    c, lew, root = lew_setup
    zpl = "Define Employee as a users."
    await c.put("/api/namespace/zpl", json={"text": zpl})
    resp = await c.get("/api/namespace/zpl")
    text = resp.json()["text"]
    assert "Employee" in text
    assert "Lew.Employee" not in text


async def test_empty_namespace_returns_empty(db, lew_setup):
    c, _, _ = lew_setup
    resp = await c.get("/api/namespace/zpl")
    assert resp.status_code == 200
    assert resp.json()["text"] == ""


async def test_child_namespace_zpl_stored_separately(db, corp_setup):
    """Corp namespace ZPL is stored under corp_ns.id, not root_ns.id."""
    c, lew, root, corp = corp_setup
    zpl = "Define Manager as a users."
    await c.put("/api/namespace/zpl", json={"text": zpl})

    corp_stored = await db.get_namespace_zpl(corp["id"])
    root_stored = await db.get_namespace_zpl(root["id"])
    assert "Corp.Manager" in corp_stored
    assert not root_stored or "Corp.Manager" not in root_stored


# ── get all ZPL ───────────────────────────────────────────────────────────────

async def test_get_all_zpl_shows_full_path(db, lew_setup):
    """GET /api/namespace/zpl/all assembles full dotted path for each namespace."""
    c, lew, root = lew_setup
    await c.put("/api/namespace/zpl", json={"text": "Define Employee as a users."})

    corp = await db.create_namespace("Corp", lew["id"], root["id"])
    corp_cookie = make_session(lew["id"], "lew", "Lew", corp["id"], "Corp")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c2:
        c2.cookies.set("session", corp_cookie)
        await c2.put("/api/namespace/zpl", json={"text": "Define Manager as a users."})

    resp = await c.get("/api/namespace/zpl/all")
    assert resp.status_code == 200
    combined = resp.json()["text"]
    assert "Lew.Employee" in combined
    assert "Lew.Corp.Manager" in combined


# ── ZPL keyed by namespace_id in DB ──────────────────────────────────────────

async def test_batch_fetch_returns_correct_namespace_ids(db, users):
    lew_id = users["lew"]["id"]
    alice_id = users["alice"]["id"]
    root = await db.get_or_create_root_namespace(lew_id, "Lew")
    corp = await db.create_namespace("Corp", alice_id, root["id"])

    await db.save_namespace_zpl(root["id"], "Define X as a users.")
    await db.save_namespace_zpl(corp["id"], "Define Y as a users.")

    result = await db.get_namespace_zpl_batch([root["id"], corp["id"]])
    assert root["id"] in result
    assert corp["id"] in result
    assert "X" in result[root["id"]]
    assert "Y" in result[corp["id"]]


async def test_delete_namespace_clears_zpl(db, users):
    lew_id = users["lew"]["id"]
    root = await db.get_or_create_root_namespace(lew_id, "Lew")
    corp = await db.create_namespace("Corp", lew_id, root["id"])
    await db.save_namespace_zpl(corp["id"], "Define X as a users.")
    await db.delete_namespace(corp["id"])
    assert await db.get_namespace_zpl(corp["id"]) == ""


# ── rename cascade re-prefix ──────────────────────────────────────────────────

async def test_rename_cascades_zpl_reprefix(db, lew_setup):
    """Renaming a namespace re-prefixes stored ZPL from old name to new name."""
    c, lew, root = lew_setup
    await c.put("/api/namespace/zpl", json={"text": "Define Employee as a users."})

    stored_before = await db.get_namespace_zpl(root["id"])
    assert "Lew.Employee" in stored_before

    resp = await c.patch(f"/api/namespaces/{root['id']}", json={"display_name": "Acme"})
    assert resp.status_code == 200

    stored_after = await db.get_namespace_zpl(root["id"])
    assert "Acme.Employee" in stored_after
    assert "Lew.Employee" not in stored_after


async def test_rename_no_zpl_is_noop(db, lew_setup):
    """Renaming a namespace with no ZPL stored doesn't error."""
    c, lew, root = lew_setup
    resp = await c.patch(f"/api/namespaces/{root['id']}", json={"display_name": "Acme"})
    assert resp.status_code == 200
    assert await db.get_namespace_zpl(root["id"]) == ""


async def test_rename_preserves_unrelated_zpl_content(db, lew_setup):
    """Rename only changes the prefix, not unrelated content."""
    c, lew, root = lew_setup
    await c.put("/api/namespace/zpl", json={
        "text": "Define Employee as a users.\nAllow employees to access services."
    })
    await c.patch(f"/api/namespaces/{root['id']}", json={"display_name": "Acme"})
    stored = await db.get_namespace_zpl(root["id"])
    assert "Acme.Employee" in stored
    assert "Allow" in stored


# ── merged policy set uses namespace tree ─────────────────────────────────────

async def test_merged_uses_namespace_tree(db, lew_setup):
    """/api/parse and match endpoints work through namespace tree, not user tree."""
    c, lew, root = lew_setup
    zpl = "Define Employee as a users.\nAllow employees to access services."
    await c.put("/api/namespace/zpl", json={"text": zpl})

    resp = await c.post("/api/parse", json={"text": zpl})
    assert resp.status_code == 200
    data = resp.json()
    assert not data.get("errors")
