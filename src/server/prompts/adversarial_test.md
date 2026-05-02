You are processing a ZPL (Zero-trust Policy Language) policy test suite. You have two tasks.

## Task 1 — Polish test titles

Rewrite each positive test title as a natural English sentence describing a realistic situation.
- Replace class/attribute notation with plain language descriptions
- Always use "tries to" phrasing (e.g. "tries to access", "tries to connect")
- Keep each title concise (under 15 words)

## Task 2 — Generate adversarial counter-tests

From the allow tests provided, generate exactly {n_adversarial} adversarial near-miss variants that should be DENIED.

You may draw from any of the allow tests and may generate multiple variants from the same rule — each variant must use a DIFFERENT mutation strategy or target a DIFFERENT attribute/slot.

### Class hierarchy

The policy uses the following class definitions. You MUST consult this before applying Strategy A.

{classes_json}

Each entry lists the class name, its parent, and its direct subclasses. Subclass relationships are transitive: if B is a subclass of A, and C is a subclass of B, then C is also a subclass of A.

**CRITICAL for Strategy A:** A rule that requires class X will also match any subclass of X. If you replace the subject or object with a subclass of what the rule requires, the rule will still fire — the test will not be denied and is invalid.

### Available mutation strategies (apply one per test)

**A. Wrong class** — replace the subject or object class with one that is NOT a subclass of what the rule requires, and is NOT an ancestor of it either. Use a sibling class (same parent, different branch) or a completely unrelated class. Before choosing a replacement, check the class hierarchy above: trace the full subclass chain of your chosen class — if the rule's required class appears anywhere in that chain, choose a different class.

**B. Wrong attribute value** — if the rule constrains `attr: value`, change that attribute to a different plausible value that the rule does not allow.

**C. Remove a required attribute** — if the rule requires `attr: value`, omit that attribute key entirely from the payload.

**D. Wrong verb** — if the rule is verb-specific, change the verb to one the rule does not allow.

**E. Trigger a never rule** — construct a payload that matches a never rule that overrides the allow, resulting in deny.

CRITICAL — only apply mutations that are meaningful for what the RULE actually checks:
- The test payload only contains attributes the rule checks. Mutating attributes not in the payload will not cause a deny.
- Tags use set-overlap matching. To miss: omit the tags key (strategy C) or use a tag the rule does not require.

For each adversarial test:
- Start from an allow test payload
- Apply exactly ONE mutation from the list above
- Keep all other slots and attributes identical
- The title should describe the near-miss situation clearly using "tries to" phrasing

You MUST produce exactly {n_adversarial} counter_tests entries — no more, no fewer.

## Input

Positive tests (to polish):
{positive_tests_json}

Allow tests available for adversarial generation:
{allow_tests_json}

## Response format

Return a single JSON object. Payloads use the /api/match format:

{"positive_tests": [{"number": 1, "title": "A sales manager tries to access the customer database"}], "counter_tests": [{"number": 1, "title": "A contractor tries to access the customer database", "rule_name": "Name of rule this targets", "expected": "deny", "payload": {"subject_class": "employee", "subject_attrs": {"employment-type": "contract"}, "action": "access", "object_class": "database", "object_attrs": {"data": "customer"}}}]}

Return only the JSON object, no other text.
