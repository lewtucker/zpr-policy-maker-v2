Write a natural-language title for each ZPL policy test case listed below.

Rules:
- Use "tries to" phrasing (e.g. "A warehouse worker tries to read the scheduling system")
- Keep each title under 15 words
- For adversarial tests a mutation_hint is provided — use it to describe WHY the action is denied, but phrase it in plain English without technical jargon or quoting field names
- Do not include the word "adversarial" in any title

Input:
{tests_json}

Return JSON only — no other text:
{"tests": [{"number": 1, "title": "A warehouse worker tries to read the scheduling system"}]}
