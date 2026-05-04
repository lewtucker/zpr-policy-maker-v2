# Test Generator Tests

Tests the `/api/tests/adversarial` endpoint. Each test generates a test suite
for a namespace, then runs all generated tests via `/api/match` and checks pass rates.

## Test Cases

| # | Namespace | Checks |
|---|-----------|--------|
| 1 | Warehouse | ≥1 positive test returned; ≥1 adversarial test returned; all positive tests pass (verdict matches expected); titles are under 15 words and don't contain "adversarial" |
| 2 | Hr | ≥1 positive test returned; all positive tests pass (ancestor class resolution working); adversarial deny tests pass |
| 3 | Corp | Handles namespace with only Never rules (no Allow rules); adversarial tests still generated if possible |

## Pass criteria

- **Positive tests**: generated expected=allow tests should return verdict=allow
- **Adversarial tests**: generated expected=deny tests should return verdict=deny  
- **Titles**: all titles non-empty, ≤15 words, no word "adversarial"
- **No crashes**: endpoint returns 200 with valid JSON
