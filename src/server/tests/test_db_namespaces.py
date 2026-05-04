"""Stage 1 tests: namespaces table DB functions."""
import pytest


# ── create / get ──────────────────────────────────────────────────────────────

async def test_create_and_get(db, users):
    lew_id = users["lew"]["id"]
    ns = await db.create_namespace("Corp", lew_id)
    assert ns["display_name"] == "Corp"
    assert ns["owner_user_id"] == lew_id
    assert ns["parent_namespace_id"] is None
    assert ns["id"]

    fetched = await db.get_namespace(ns["id"])
    assert fetched["display_name"] == "Corp"
    assert fetched["owner_user_id"] == lew_id


async def test_get_missing_returns_none(db):
    assert await db.get_namespace("nonexistent") is None


async def test_create_child(db, users):
    lew_id = users["lew"]["id"]
    corp = await db.create_namespace("Corp", lew_id)
    it   = await db.create_namespace("IT", lew_id, corp["id"])
    assert it["parent_namespace_id"] == corp["id"]


# ── update ────────────────────────────────────────────────────────────────────

async def test_update_display_name(db, users):
    ns = await db.create_namespace("Corp", users["lew"]["id"])
    await db.update_namespace(ns["id"], display_name="Acme")
    updated = await db.get_namespace(ns["id"])
    assert updated["display_name"] == "Acme"


async def test_update_owner(db, users):
    ns = await db.create_namespace("Corp", users["lew"]["id"])
    await db.update_namespace(ns["id"], owner_user_id=users["alice"]["id"])
    updated = await db.get_namespace(ns["id"])
    assert updated["owner_user_id"] == users["alice"]["id"]


async def test_update_noop(db, users):
    ns = await db.create_namespace("Corp", users["lew"]["id"])
    await db.update_namespace(ns["id"])  # no kwargs — should not raise
    unchanged = await db.get_namespace(ns["id"])
    assert unchanged["display_name"] == "Corp"


# ── delete ────────────────────────────────────────────────────────────────────

async def test_delete_leaf(db, users):
    lew_id = users["lew"]["id"]
    corp = await db.create_namespace("Corp", lew_id)
    it   = await db.create_namespace("IT",   lew_id, corp["id"])
    err = await db.delete_namespace(it["id"])
    assert err is None
    assert await db.get_namespace(it["id"]) is None


async def test_delete_with_children_blocked(db, users):
    lew_id = users["lew"]["id"]
    corp = await db.create_namespace("Corp", lew_id)
    await db.create_namespace("IT", lew_id, corp["id"])
    err = await db.delete_namespace(corp["id"])
    assert err is not None
    assert await db.get_namespace(corp["id"]) is not None


# ── tree ──────────────────────────────────────────────────────────────────────

async def test_tree_structure(db, tree):
    t = await db.get_namespace_tree(tree["corp"]["id"])
    assert t["display_name"] == "Corp"
    child_names = {c["display_name"] for c in t["children"]}
    assert child_names == {"HQ", "IT"}


async def test_tree_nested(db, tree):
    t = await db.get_namespace_tree(tree["corp"]["id"])
    it_node = next(c for c in t["children"] if c["display_name"] == "IT")
    assert len(it_node["children"]) == 1
    assert it_node["children"][0]["display_name"] == "Dev"


async def test_tree_unknown_root_returns_empty(db):
    t = await db.get_namespace_tree("nonexistent")
    assert t == {}


async def test_tree_includes_owner_username(db, tree):
    t = await db.get_namespace_tree(tree["corp"]["id"])
    assert t["owner_username"] == "lew"
    it_node = next(c for c in t["children"] if c["display_name"] == "IT")
    assert it_node["owner_username"] == "alice"


# ── get_namespaces_owned_by ───────────────────────────────────────────────────

async def test_get_namespaces_owned_by(db, tree):
    owned = await db.get_namespaces_owned_by(tree["alice_id"])
    names = {n["display_name"] for n in owned}
    assert names == {"IT", "Dev"}


async def test_get_namespaces_owned_by_empty(db, users):
    owned = await db.get_namespaces_owned_by(users["bob"]["id"])
    assert owned == []


# ── can_access_namespace ──────────────────────────────────────────────────────

async def test_direct_owner_can_access(db, tree):
    assert await db.can_access_namespace(tree["alice_id"], tree["it"]["id"])


async def test_ancestor_owner_can_access(db, tree):
    # lew owns Corp, which is parent of IT (owned by alice) — lew can still access IT
    assert await db.can_access_namespace(tree["lew_id"], tree["it"]["id"])


async def test_grandparent_can_access_grandchild(db, tree):
    # lew owns Corp → Corp.IT → Corp.IT.Dev (all under Corp)
    assert await db.can_access_namespace(tree["lew_id"], tree["it_dev"]["id"])


async def test_owner_can_access_own_root(db, tree):
    assert await db.can_access_namespace(tree["lew_id"], tree["corp"]["id"])


async def test_stranger_cannot_access(db, tree):
    assert not await db.can_access_namespace(tree["bob_id"], tree["it"]["id"])


async def test_sibling_cannot_access(db, tree):
    # alice owns IT but not HQ (both under Corp)
    assert not await db.can_access_namespace(tree["alice_id"], tree["hq"]["id"])


async def test_child_owner_cannot_access_parent(db, tree):
    # alice owns IT but not Corp
    assert not await db.can_access_namespace(tree["alice_id"], tree["corp"]["id"])


# ── reassign_orphaned_namespaces ──────────────────────────────────────────────

async def test_reassign_on_owner_removal(db, tree):
    # alice owns IT and Dev; lew owns Corp (parent of IT)
    # Remove alice as owner → IT and Dev should go to lew
    await db.reassign_orphaned_namespaces(tree["alice_id"])
    it  = await db.get_namespace(tree["it"]["id"])
    dev = await db.get_namespace(tree["it_dev"]["id"])
    assert it["owner_user_id"]  == tree["lew_id"]
    assert dev["owner_user_id"] == tree["lew_id"]


async def test_reassign_skips_root_with_no_ancestor(db, users):
    # Root namespace (no parent) owned by alice — nothing to reassign to
    lew_id   = users["lew"]["id"]
    alice_id = users["alice"]["id"]
    root = await db.create_namespace("AliceRoot", alice_id)
    await db.reassign_orphaned_namespaces(alice_id)
    # Still owned by alice — no ancestor found, left unchanged
    ns = await db.get_namespace(root["id"])
    assert ns["owner_user_id"] == alice_id


async def test_reassign_chain(db, users):
    # lew → Corp (lew) → IT (alice) → Dev (bob)
    # Remove bob → Dev goes to alice (nearest non-bob ancestor)
    lew_id   = users["lew"]["id"]
    alice_id = users["alice"]["id"]
    bob_id   = users["bob"]["id"]
    corp = await db.create_namespace("Corp", lew_id)
    it   = await db.create_namespace("IT",   alice_id, corp["id"])
    dev  = await db.create_namespace("Dev",  bob_id,   it["id"])
    await db.reassign_orphaned_namespaces(bob_id)
    dev_ns = await db.get_namespace(dev["id"])
    assert dev_ns["owner_user_id"] == alice_id
