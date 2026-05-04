# Test Generator Tests — Results

## Warehouse — ERROR: namespace not found

## Hr — **PASS**

Generated: 2 positive, 4 adversarial

Positive: 2/2 pass | Adversarial: 4/4 pass

**Positive tests:**
- ✓ [allow→allow] An employee tries to access an HR-tagged database
- ✓ [allow→allow] An employee tries to access the employee database

**Adversarial tests:**
- ✓ [deny→deny] An employee tries to read an HR database using the wrong action
- ✓ [deny→deny] An employee tries to read the employee database using the wrong action
- ✓ [deny→deny] An employee tries to access a database with an invalid subject tag
- ✓ [deny→deny] An employee tries to access a database with an invalid resource tag

## Corp — **PASS**

Generated: 3 positive, 4 adversarial

Positive: 3/3 pass | Adversarial: 4/4 pass

**Positive tests:**
- ✓ [allow→allow] An employee tries to access the employee database
- ✓ [allow→allow] An employee tries to access an HR-tagged database as an HR user
- ✓ [deny→deny] An intern user tries to access a restricted service

**Adversarial tests:**
- ✓ [deny→deny] An employee tries to read the employee database using the wrong action
- ✓ [deny→deny] An employee tries to read an HR database instead of accessing it
- ✓ [deny→deny] An employee tries to access a database they have no permission for
- ✓ [deny→deny] An employee tries to access an HR gateway they are not permitted to use

