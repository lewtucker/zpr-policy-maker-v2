"""Shared pytest fixtures for ZPR Policy Maker tests."""
import pytest
import pytest_asyncio
import sys
import os

# Ensure src/server is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import database as db_module


@pytest_asyncio.fixture
async def db(tmp_path):
    """Fresh isolated database for each test."""
    db_path = str(tmp_path / "test.db")
    original = db_module._DB_PATH
    db_module._DB_PATH = db_path
    await db_module.init_db()
    yield db_module
    db_module._DB_PATH = original


@pytest_asyncio.fixture
async def users(db):
    """Three test users: lew (root), alice, bob."""
    lew   = await db.create_user("lew",   "password", display_name="Lew")
    alice = await db.create_user("alice", "password", display_name="Alice")
    bob   = await db.create_user("bob",   "password", display_name="Bob")
    return {"lew": lew, "alice": alice, "bob": bob}


@pytest_asyncio.fixture
async def tree(db, users):
    """
    Namespace tree:
      Corp          (owner: lew)
        Corp.HQ     (owner: lew)
        Corp.IT     (owner: alice)
          Corp.IT.Dev  (owner: alice)
    """
    lew_id   = users["lew"]["id"]
    alice_id = users["alice"]["id"]

    corp      = await db.create_namespace("Corp",    lew_id)
    hq        = await db.create_namespace("HQ",      lew_id,   corp["id"])
    it        = await db.create_namespace("IT",       alice_id, corp["id"])
    it_dev    = await db.create_namespace("Dev",      alice_id, it["id"])

    return {"corp": corp, "hq": hq, "it": it, "it_dev": it_dev,
            "lew_id": lew_id, "alice_id": alice_id, "bob_id": users["bob"]["id"]}
