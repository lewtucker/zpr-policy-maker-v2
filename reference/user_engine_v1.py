"""Per-user bridge between SQLite storage and the ZPL engine.

Composition:
    database.get_*_yaml(email)  →  YAML strings
    system + user classes       →  merged ClassSchema
    rules YAML                  →  list[Rule]
    entities YAML               →  list[Entity]
    ZPLEngine(rules, schema)    →  ready evaluator

System classes ship with the server at ``defaults/system_classes.yaml``.
User-defined classes come from the user's ``classes_yaml`` column and are
merged on top of the system classes. Attempting to override a ``builtin: true``
class raises :class:`ClassSchemaError`.

Named-entity lookup is provided by :func:`build_entity_index`; the ``/check``
endpoint uses it to resolve ``Timesheet-database`` and other named references
to concrete :class:`Entity` instances.
"""
from __future__ import annotations

import uuid
from pathlib import Path

import yaml

import database
from class_schema import ClassSchema, ClassSchemaError
from zpl_engine import Entity, Rule, ZPLEngine, dump_rules, load_rules

# ── System schema (shipped with server, loaded once per process) ────────────

SYSTEM_CLASSES_PATH: Path = Path(__file__).parent / "defaults" / "system_classes.yaml"

_system_classes_cache: list[dict] | None = None


def _load_system_classes() -> list[dict]:
    """Load and cache the shipped ``system_classes.yaml``."""
    global _system_classes_cache
    if _system_classes_cache is None:
        with open(SYSTEM_CLASSES_PATH) as f:
            data = yaml.safe_load(f) or {}
        classes = data.get("classes") or []
        if not isinstance(classes, list):
            raise ClassSchemaError(
                f"{SYSTEM_CLASSES_PATH}: 'classes' must be a list"
            )
        _system_classes_cache = classes
    return _system_classes_cache


def reset_system_classes_cache() -> None:
    """Force a reload of the system schema (primarily for tests)."""
    global _system_classes_cache
    _system_classes_cache = None


# ── Class schema (system + user) ────────────────────────────────────────────


def load_user_schema(email: str) -> ClassSchema:
    """Return the merged system + user ClassSchema for this user.

    Raises:
        ClassSchemaError: if a user class tries to override a builtin, or if
            any validation in :class:`ClassSchema` fails.
    """
    system = _load_system_classes()
    user_classes = _load_user_classes_list(email)

    merged: dict[str, dict] = {c["class"]: c for c in system if c.get("class")}
    for c in user_classes:
        cname = c.get("class")
        if not cname:
            continue  # malformed entry — skip silently (validator will flag)
        existing = merged.get(cname)
        if existing and existing.get("builtin"):
            raise ClassSchemaError(
                f"User class {cname!r} cannot override builtin: true class"
            )
        merged[cname] = c
    return ClassSchema(list(merged.values()))


def _load_user_classes_list(email: str) -> list[dict]:
    yaml_str = database.get_classes_yaml(email)
    data = yaml.safe_load(yaml_str) or {}
    if not isinstance(data, dict):
        return []
    classes = data.get("classes") or []
    return classes if isinstance(classes, list) else []


def save_user_classes(email: str, classes: list[dict]) -> None:
    """Persist user-defined classes. ``builtin: true`` entries are rejected."""
    for c in classes:
        if c.get("builtin"):
            raise ClassSchemaError(
                f"User cannot save builtin: true class {c.get('class')!r}"
            )
    yaml_str = yaml.safe_dump(
        {"classes": classes}, sort_keys=False, default_flow_style=False
    )
    database.save_classes(email, yaml_str)


# ── Rules ───────────────────────────────────────────────────────────────────


def load_user_rules(email: str) -> list[Rule]:
    return load_rules(database.get_rules_yaml(email))


def save_user_rules(email: str, rules: list[Rule]) -> None:
    database.save_rules(email, dump_rules(rules))


# ── Entities ────────────────────────────────────────────────────────────────


def load_user_entities(email: str) -> list[Entity]:
    """Load the user's entity roster from YAML.

    YAML shape (see docs/RFC_entities.yaml)::

        entities:
          - id: <uuid>
            class: employee
            name: Ted
            attributes:
              department: sales
              ...
    """
    yaml_str = database.get_entities_yaml(email)
    data = yaml.safe_load(yaml_str) or {}
    if not isinstance(data, dict):
        return []
    entries = data.get("entities") or []
    if not isinstance(entries, list):
        return []
    out: list[Entity] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cls_name = entry.get("class")
        if not cls_name:
            continue
        out.append(
            Entity(
                class_name=cls_name,
                name=entry.get("name") or None,
                attrs=dict(entry.get("attributes") or {}),
            )
        )
    return out


def save_user_entities(
    email: str,
    entities: list[Entity],
    *,
    ids: list[str | None] | None = None,
) -> None:
    """Serialize entities back to YAML and save.

    ``ids`` lets callers preserve existing UUIDs when updating. If an id is
    falsy, a fresh UUID is generated.
    """
    if ids is not None and len(ids) != len(entities):
        raise ValueError("ids must have the same length as entities")
    data_entries = []
    for i, e in enumerate(entities):
        existing_id = ids[i] if ids else None
        data_entries.append(
            {
                "id": existing_id or uuid.uuid4().hex,
                "class": e.class_name,
                "name": e.name,
                "attributes": dict(e.attrs),
            }
        )
    yaml_str = yaml.safe_dump(
        {"entities": data_entries}, sort_keys=False, default_flow_style=False
    )
    database.save_entities(email, yaml_str)


def build_entity_index(entities: list[Entity]) -> dict[str, Entity]:
    """Index entities by name for O(1) named-reference resolution.

    Entities without a name are skipped. On duplicate names, the later entry wins.
    """
    return {e.name: e for e in entities if e.name}


def resolve_entity(name: str, index: dict[str, Entity]) -> Entity | None:
    return index.get(name)


# ── Composite: build a ready engine ─────────────────────────────────────────


def load_engine(email: str) -> ZPLEngine:
    """Load schema + rules for a user and return a ZPLEngine."""
    schema = load_user_schema(email)
    rules = load_user_rules(email)
    return ZPLEngine(rules, schema)
