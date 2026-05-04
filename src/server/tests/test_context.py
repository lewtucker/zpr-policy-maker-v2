"""Stage 2 tests: root namespace creation and context resolution."""
import pytest


# ── get_or_create_root_namespace ──────────────────────────────────────────────

async def test_creates_root_namespace(db, users):
    lew_id = users["lew"]["id"]
    ns = await db.get_or_create_root_namespace(lew_id, "Lew")
    assert ns["owner_user_id"] == lew_id
    assert ns["display_name"] == "Lew"
    assert ns["parent_namespace_id"] is None
    assert ns["id"]


async def test_idempotent(db, users):
    lew_id = users["lew"]["id"]
    ns1 = await db.get_or_create_root_namespace(lew_id, "Lew")
    ns2 = await db.get_or_create_root_namespace(lew_id, "Lew")
    assert ns1["id"] == ns2["id"]


async def test_idempotent_ignores_new_display_name(db, users):
    """Second call with a different display_name returns existing, not a new one."""
    lew_id = users["lew"]["id"]
    ns1 = await db.get_or_create_root_namespace(lew_id, "Lew")
    ns2 = await db.get_or_create_root_namespace(lew_id, "LewRenamed")
    assert ns1["id"] == ns2["id"]
    assert ns2["display_name"] == "Lew"  # original preserved


async def test_each_user_gets_own_root(db, users):
    lew_ns   = await db.get_or_create_root_namespace(users["lew"]["id"],   "Lew")
    alice_ns = await db.get_or_create_root_namespace(users["alice"]["id"], "Alice")
    assert lew_ns["id"] != alice_ns["id"]
    assert lew_ns["owner_user_id"]   == users["lew"]["id"]
    assert alice_ns["owner_user_id"] == users["alice"]["id"]


async def test_get_root_namespace_returns_none_before_create(db, users):
    result = await db.get_root_namespace(users["bob"]["id"])
    assert result is None


# ── root namespace does not replace child-level namespaces ────────────────────

async def test_child_namespace_not_returned_as_root(db, users):
    """If user owns only a child namespace (no root), get_root_namespace returns None."""
    lew_id   = users["lew"]["id"]
    alice_id = users["alice"]["id"]
    corp = await db.create_namespace("Corp", lew_id)
    await db.create_namespace("IT", alice_id, corp["id"])  # alice owns a child, not a root
    assert await db.get_root_namespace(alice_id) is None


async def test_get_or_create_creates_when_only_child_exists(db, users):
    """get_or_create creates a root even if user owns a child namespace."""
    lew_id   = users["lew"]["id"]
    alice_id = users["alice"]["id"]
    corp = await db.create_namespace("Corp", lew_id)
    await db.create_namespace("IT", alice_id, corp["id"])
    root = await db.get_or_create_root_namespace(alice_id, "Alice")
    assert root["parent_namespace_id"] is None
    assert root["owner_user_id"] == alice_id


# ── can_access_namespace re-verified post-root-create ────────────────────────

async def test_user_can_access_own_root(db, users):
    lew_id = users["lew"]["id"]
    root = await db.get_or_create_root_namespace(lew_id, "Lew")
    assert await db.can_access_namespace(lew_id, root["id"])


async def test_user_cannot_access_other_root(db, users):
    lew_id   = users["lew"]["id"]
    alice_id = users["alice"]["id"]
    lew_root = await db.get_or_create_root_namespace(lew_id, "Lew")
    assert not await db.can_access_namespace(alice_id, lew_root["id"])


async def test_login_owner_can_access_child_namespace(db, users):
    """After creating a child namespace under lew's root, lew can access it."""
    lew_id = users["lew"]["id"]
    root   = await db.get_or_create_root_namespace(lew_id, "Lew")
    child  = await db.create_namespace("Corp", lew_id, root["id"])
    assert await db.can_access_namespace(lew_id, child["id"])


async def test_delegated_owner_cannot_access_peer_namespace(db, users):
    """alice owns 'IT' under lew's root; alice cannot access 'HQ' (also under lew's root)."""
    lew_id   = users["lew"]["id"]
    alice_id = users["alice"]["id"]
    root  = await db.get_or_create_root_namespace(lew_id, "Lew")
    it    = await db.create_namespace("IT",  alice_id, root["id"])
    hq    = await db.create_namespace("HQ",  lew_id,   root["id"])
    assert await db.can_access_namespace(alice_id, it["id"])
    assert not await db.can_access_namespace(alice_id, hq["id"])
