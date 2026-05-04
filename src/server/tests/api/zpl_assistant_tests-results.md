# ZPL Assistant Tests — Results

**2 PASS  0 FAIL** (of 6)

### 1. Warehouse: define part-time worker — **SKIP**

**Generated:** `namespace 'Warehouse' not found`


### 2. Corp: never allow interns — **PASS**

**Generated:** `Never allow tags:intern employee to access tags:financial database.`

**Reply:** Added a rule that prevents intern employees from accessing financial-tagged data

**Checks:**
- ✓ intent=generate
- ✓ uses 'tags:intern' not bare 'intern'
- ✓ starts with 'Never'
- ✓ ZPL parses without errors

### 3. Warehouse: allow managers to access hr system — **SKIP**

**Generated:** `namespace 'Warehouse' not found`


### 4. Hr: define sales employee (no ns prefix on new class) — **PASS**

**Generated:** `Define sales-employee as a Corp.employee with tags sales.`

**Reply:** Defines a new class 'sales-employee' extending Corp.employee, tagged with 'sales

**Checks:**
- ✓ intent=generate
- ✓ new class name not prefixed with 'Hr.'
- ✓ ZPL parses without errors

### 5. Warehouse: question about classes — **SKIP**

**Generated:** `namespace 'Warehouse' not found`


### 6. Error path: parse error statement — **SKIP**

**Generated:** `namespace 'Warehouse' not found`


