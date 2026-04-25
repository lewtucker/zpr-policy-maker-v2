"""Thin Anthropic client wrapper for ZPR Policy Maker.

Exposes:
  - ``ANTHROPIC_MODEL`` — the default model used by every AI endpoint
  - ``available()`` — True if ANTHROPIC_API_KEY is set
  - ``complete(system, messages, ...)`` — raw text completion with prompt caching
  - ``extract_json_blocks(text, tag)`` — pull <TAG>...</TAG> blocks out of
    Claude's response and parse as JSON

Prompt caching is enabled on the system prompt (stable across turns, so
it benefits) using the standard ``cache_control`` marker.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

import anthropic

# Default model — latest Sonnet. AI endpoints use this unless overridden.
ANTHROPIC_MODEL = "claude-sonnet-4-5"


def available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def _client() -> anthropic.Anthropic:
    return anthropic.Anthropic()


def complete(
    system: str,
    messages: list[dict[str, Any]],
    *,
    model: str = ANTHROPIC_MODEL,
    max_tokens: int = 2048,
    temperature: float = 0.2,
) -> str:
    """Call Claude with prompt caching on the system prompt.

    Returns the concatenated text content of the response.
    """
    client = _client()
    # Mark the system prompt as cacheable so repeated calls benefit
    system_blocks = [
        {"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}
    ]
    resp = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        system=system_blocks,
        messages=messages,
    )
    parts = []
    for block in resp.content:
        if getattr(block, "type", None) == "text":
            parts.append(block.text)
    return "".join(parts)


def extract_json_blocks(text: str, tag: str) -> list[dict]:
    """Extract and parse all ``<TAG>...</TAG>`` blocks as JSON.

    Malformed blocks are silently skipped.
    """
    pattern = rf"<{re.escape(tag)}>\s*(.*?)\s*</{re.escape(tag)}>"
    out: list[dict] = []
    for raw in re.findall(pattern, text, flags=re.DOTALL):
        # Try direct parse first
        try:
            out.append(json.loads(raw))
            continue
        except json.JSONDecodeError:
            pass
        # Strip optional ```json fences
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip(), flags=re.DOTALL)
        try:
            out.append(json.loads(cleaned))
        except json.JSONDecodeError:
            pass
    return out


def strip_tagged_blocks(text: str, tag: str) -> str:
    """Remove all ``<TAG>...</TAG>`` blocks, returning the surrounding prose."""
    pattern = rf"<{re.escape(tag)}>.*?</{re.escape(tag)}>"
    return re.sub(pattern, "", text, flags=re.DOTALL).strip()
