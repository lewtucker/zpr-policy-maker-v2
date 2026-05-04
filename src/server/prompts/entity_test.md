You are processing a ZPL (Zero-trust Policy Language) policy test suite. You have two tasks.

## Task 1 — Polish test titles

Rewrite EVERY test title (both allow AND deny) as a natural English sentence describing a realistic situation.
- Use the entity name where available — check the payload for "subject_name" and "object_name" fields
- Always use "tries to" phrasing (e.g. "Grace tries to access Payroll-DB")
- For deny tests: phrase them the same way — just describe the access attempt, not the outcome
- Keep each title concise (under 15 words)
- You MUST return a title for every test number in the input, including deny tests

## Task 2 — Generate adversarial counter-tests

From the allow tests provided, generate exactly {n_adversarial} adversarial near-miss variants that should be DENIED.

You may draw from any of the allow tests and may generate multiple variants from the same rule — each variant must use a DIFFERENT mutation strategy or target a DIFFERENT attribute/slot. This lets you exceed the number of rules when more tests are requested.

### Class hierarchy

The policy uses the following class definitions. You MUST consult this before applying Strategy A.

{classes_json}

**CRITICAL for Strategy A:** A rule that requires class X will also match any subclass of X. If you replace the subject or object with a subclass of what the rule requires, the rule will still fire — the test will not be denied and is invalid. Trace the full subclass chain before choosing a replacement.

### Available entities

Use real entity names from this list when applying Strategy D. Do NOT invent entity names.

{entities_section}

### Mutation strategies (apply exactly one per test)

**A. Wrong class** — replace the subject or object class with a sibling or completely unrelated class that is NOT a subclass of what the rule requires. Check the hierarchy carefully before choosing.

**B. Wrong attribute value** — change a constrained attribute to a different plausible value the rule does not allow (e.g. change `department: operations` to `department: finance`).

**C. Remove a required attribute** — omit a required attribute key entirely from the payload. The engine treats a missing attribute as a non-match, causing a deny.

**D. Wrong entity** — substitute a different named entity from the same general class (users stay users, services stay services) that would NOT satisfy the rule's constraints. Pick a real entity from the "Available entities" list above.

**E. Wrong verb** — change the verb to one the rule does not allow (e.g. change `operate` to `read`).

**F. Trigger a never rule** — construct a payload that matches a never/deny rule that overrides the allow.

CRITICAL rules:
- Only mutate what the rule actually checks. Mutating irrelevant attributes will not cause a deny.
- For Strategy D: use only real entity names from the "Available entities" list. Do NOT use a human/worker entity as an object (resource), or a service/machine entity as a subject (actor).
- Tags use set-overlap matching. To miss: omit the tags key entirely (Strategy C).
- Never repeat the same mutation on the same rule.

For each adversarial test:
- Start from a positive allow test payload
- Apply exactly ONE mutation from the strategies above
- Keep all other slots and attributes identical
- Title should use the entity name where available ("Grace tries to..." not "A floor-worker tries to...")

You MUST produce exactly {n_adversarial} counter_tests entries — no more, no fewer.

## Input

All tests to polish (both allow and deny — return a title for every number):
{positive_tests_json}

Allow tests available for adversarial generation:
{allow_tests_json}

## Response format

Return a single JSON object. Payloads use the /api/match format:

{"positive_tests": [{"number": 1, "title": "Alice tries to access Inventory-DB"}], "counter_tests": [{"number": 1, "title": "Grace tries to access Inventory-DB but lacks clearance", "expected": "deny", "payload": {"subject_class": "Corp.floor-worker", "subject_name": "Grace", "subject_attrs": {"employment-type": "part-time", "shift": "night"}, "action": "read", "object_class": "Corp.inventory-system", "object_name": "Inventory-DB", "object_attrs": {"env": "production"}}}]}

Return only the JSON object, no other text.
