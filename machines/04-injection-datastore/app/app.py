"""WSTG machine 04 - Injection / Datastore front application.

INTENTIONALLY VULNERABLE training target. Every endpoint below concatenates
user input into a query for a different datastore / dialect:

  05.1 Oracle      -> /pls/<dad>/<package>.<proc>   (mod_plsql gateway facade, PG-backed)
  05.2 MySQL       -> /mysql/*                      (real mysql:8.4)
  05.3 SQL Server  -> /mssql/*                      (real MSSQL 2022, amd64 emulation)
  05.4 PostgreSQL  -> /pg/*                         (real postgres:16)
  05.5 MS Access   -> /access/*                     (Jet-dialect facade over SQLite)
  05.6 NoSQL       -> /nosql/*                      (real mongo:7)
  05.7 ORM         -> /orm/*                        (SQLAlchemy text() misuse)
  05.8 Client-side -> /clientsql/                   (alasql in the browser)
  INJT-06 LDAP     -> /ldap/login                   (real OpenLDAP)
  INJT-07 XML      -> /xml/order, /xml/parse        (tag injection + XXE)
  INJT-09 XPath    -> /xpath/login                  (lxml XPath concat)
  INJT-26 JSON     -> /json/backend                 (last-wins parser behind first-wins front)

Loopback-published, synthetic data only. See README.md.
"""
import json
import os
import re
import sqlite3
import time
import urllib.parse

import pymysql
import psycopg2
import pymongo
import ldap3
from lxml import etree
from flask import Flask, request, jsonify, send_from_directory
from sqlalchemy import Column, Integer, String, create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

app = Flask(__name__, static_folder="static", static_url_path="/static")

MYSQL_HOST = os.environ.get("MYSQL_HOST", "mysql")
PG_HOST = os.environ.get("PG_HOST", "postgres")
MONGO_HOST = os.environ.get("MONGO_HOST", "mongo")
LDAP_HOST = os.environ.get("LDAP_HOST", "ldap")
LDAP_PORT = int(os.environ.get("LDAP_PORT", "1389"))
MSSQL_HOST = os.environ.get("MSSQL_HOST", "")  # empty => service not deployed
MSSQL_SA_PASSWORD = os.environ.get("MSSQL_SA_PASSWORD", "Str0ngP@ssw0rd!")

LDAP_BASE = "dc=lab,dc=local"
LDAP_ADMIN_DN = f"cn=admin,{LDAP_BASE}"
LDAP_ADMIN_PW = "adminpass"
LDAP_SECRET = "WSTG-M04{ldap_filter_injection}"
JSON_SECRET = "WSTG-M04{json_duplicate_key}"
ACCESS_DB = "/tmp/access.db"

SINKS = {}  # client-side SQL debug sink reports, keyed by token


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _mysql_conn(multi=False):
    flags = pymysql.constants.CLIENT.MULTI_STATEMENTS if multi else 0
    return pymysql.connect(host=MYSQL_HOST, user="webapp", password="webapppass",
                           database="shop", client_flag=flags, autocommit=True,
                           connect_timeout=5, read_timeout=30)


def _pg_conn(db="webapp"):
    return psycopg2.connect(host=PG_HOST, user="webapp", password="webapppass",
                            dbname=db, connect_timeout=5)


def _mongo():
    return pymongo.MongoClient(host=MONGO_HOST, port=27017, username="root",
                               password="rootpass", authSource="admin",
                               serverSelectionTimeoutMS=5000)["lab"]


def _ldap_conn():
    srv = ldap3.Server(LDAP_HOST, port=LDAP_PORT, get_info=ldap3.NONE)
    return ldap3.Connection(srv, user=LDAP_ADMIN_DN, password=LDAP_ADMIN_PW,
                            auto_bind=True, receive_timeout=10)


def _mssql_conn(db="shop"):
    import pymssql
    return pymssql.connect(server=MSSQL_HOST, user="sa", password=MSSQL_SA_PASSWORD,
                           database=db, autocommit=True, timeout=30, login_timeout=10)


def _rows(cur):
    return [list(r) for r in cur.fetchall()]


def _err(e):
    return jsonify({"error": f"{type(e).__name__}: {e}"}), 500


# --------------------------------------------------------------------------
# startup seeding (idempotent) for stores without init-script support
# --------------------------------------------------------------------------

def seed_access():
    con = sqlite3.connect(ACCESS_DB)
    con.executescript("""
    DROP TABLE IF EXISTS products;
    CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, order_date TEXT);
    INSERT INTO products VALUES
      (1,'Widget',9.99,'2024-01-05'),(2,'Gadget',19.99,'2024-02-10'),
      (3,'Gizmo',4.50,'2023-06-01'),(4,'Doohickey',12.0,'2024-03-15');
    DROP TABLE IF EXISTS vault;
    CREATE TABLE vault (id INTEGER PRIMARY KEY, secret TEXT);
    INSERT INTO vault VALUES (1,'WSTG-M04{jet_facade_stacked}');
    """)
    con.commit()
    con.close()


def seed_ldap():
    for attempt in range(30):
        try:
            conn = _ldap_conn()
            break
        except Exception:
            time.sleep(2)
    else:
        raise RuntimeError("LDAP not reachable")
    conn.add(LDAP_BASE, ["dcObject", "organization"], {"dc": "lab", "o": "Lab"})
    conn.add(f"ou=people,{LDAP_BASE}", "organizationalUnit", {"ou": "people"})
    people = [
        ("alice", "Alice Anderson", "Password123!", "engineer"),
        ("bob", "Bob Brown", "Password123!", "engineer"),
        ("admin", "Admin Root", "Adm1nPassword!", LDAP_SECRET),
    ]
    for uid, cn, pw, desc in people:
        conn.add(f"uid={uid},ou=people,{LDAP_BASE}", ["inetOrgPerson"],
                 {"uid": uid, "cn": cn, "sn": cn.split()[-1],
                  "mail": f"{uid}@lab.local", "userPassword": pw,
                  "description": desc})
    conn.unbind()


def seed_mssql():
    if not MSSQL_HOST:
        return
    import pymssql
    for attempt in range(60):
        try:
            con = pymssql.connect(server=MSSQL_HOST, user="sa",
                                  password=MSSQL_SA_PASSWORD, database="master",
                                  autocommit=True, login_timeout=10)
            break
        except Exception:
            time.sleep(3)
    else:
        raise RuntimeError("MSSQL not reachable")
    cur = con.cursor()
    cur.execute("IF DB_ID('shop') IS NULL CREATE DATABASE shop")
    con.close()
    con = _mssql_conn("shop")
    cur = con.cursor()
    cur.execute("""IF OBJECT_ID('products') IS NULL
        CREATE TABLE products (id INT PRIMARY KEY, name VARCHAR(100), price DECIMAL(10,2))""")
    cur.execute("IF NOT EXISTS (SELECT 1 FROM products) INSERT INTO products VALUES "
                "(1,'Widget',9.99),(2,'Gadget',19.99),(3,'Gizmo',4.50)")
    cur.execute("""IF OBJECT_ID('vault') IS NULL
        CREATE TABLE vault (id INT PRIMARY KEY, secret VARCHAR(200))""")
    cur.execute("IF NOT EXISTS (SELECT 1 FROM vault) INSERT INTO vault VALUES "
                "(1,'WSTG-M04{mssql_union_batch}')")
    con.close()


# --------------------------------------------------------------------------
# index / health
# --------------------------------------------------------------------------

@app.route("/")
def index():
    return jsonify({
        "machine": "04-injection-datastore",
        "warning": "intentionally vulnerable training target",
        "endpoints": [
            "/mysql/products?id=", "/mysql/search?q=", "/mysql/stacked?id=", "/mysql/file?id=",
            "/pg/label?text=", "/pg/items?name=", "/pg/slow?id=",
            "/pls/lab/WEB_USERS.show?p_id=", "/pls/lab/WEB_USERS.find?p_name=",
            "/mssql/products?id=", "/mssql/stacked?id=", "/mssql/slow?id=",
            "/access/products?name=",
            "/nosql/login (POST JSON or GET bracket-notation)", "/nosql/where?q=",
            "/orm/users?name=&sort=",
            "/clientsql/?name=", "/clientsql/sink?token=",
            "/ldap/login?uid=&password=",
            "/xml/order (POST form)", "/xml/parse (POST raw XML)",
            "/xpath/login?user=&pass=",
            "/json/backend (POST raw JSON, via jsonfront :8401)",
        ],
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/health/deep")
def health_deep():
    checks = {}
    for name, fn in [
        ("mysql", lambda: _mysql_conn().cursor().execute("SELECT 1")),
        ("postgres", lambda: _pg_conn().cursor().execute("SELECT 1")),
        ("mongo", lambda: _mongo().command("ping")),
        ("ldap", lambda: _ldap_conn().unbind()),
        ("access", lambda: sqlite3.connect(ACCESS_DB).execute("SELECT 1")),
    ]:
        try:
            fn()
            checks[name] = "ok"
        except Exception as e:
            checks[name] = str(e)
    if MSSQL_HOST:
        try:
            _mssql_conn().cursor().execute("SELECT 1")
            checks["mssql"] = "ok"
        except Exception as e:
            checks["mssql"] = str(e)
    return jsonify(checks)


# --------------------------------------------------------------------------
# 05.2 MySQL - real mysql:8.4
# --------------------------------------------------------------------------

@app.route("/mysql/products")
def mysql_products():
    pid = request.args.get("id", "1")
    sql = f"SELECT id,name,price FROM products WHERE id={pid}"  # VULNERABLE
    try:
        con = _mysql_conn()
        cur = con.cursor()
        cur.execute(sql)
        rows = _rows(cur)
        con.close()
        return jsonify({"dialect": "mysql", "query": sql, "rows": rows})
    except Exception as e:
        return _err(e)


@app.route("/mysql/search")
def mysql_search():
    q = request.args.get("q", "")
    sql = f"SELECT id,name FROM products WHERE name LIKE '%{q}%'"  # VULNERABLE (boolean-blind)
    try:
        con = _mysql_conn()
        cur = con.cursor()
        cur.execute(sql)
        rows = _rows(cur)
        con.close()
        return jsonify({"dialect": "mysql", "query": sql, "count": len(rows), "rows": rows})
    except Exception as e:
        return _err(e)


@app.route("/mysql/stacked")
def mysql_stacked():
    pid = request.args.get("id", "1")
    sql = f"SELECT id,name FROM products WHERE id={pid}"  # VULNERABLE (multi-statement)
    try:
        con = _mysql_conn(multi=True)
        cur = con.cursor()
        cur.execute(sql)
        sets = []
        while True:
            if cur.description:
                sets.append(_rows(cur))
            if not cur.nextset():
                break
        con.close()
        return jsonify({"dialect": "mysql", "query": sql, "result_sets": sets})
    except Exception as e:
        return _err(e)


@app.route("/mysql/file")
def mysql_file():
    pid = request.args.get("id", "1")
    sql = f"SELECT id,name,price FROM products WHERE id={pid}"  # VULNERABLE (LOAD_FILE variant)
    try:
        con = _mysql_conn()
        cur = con.cursor()
        cur.execute(sql)
        rows = [[c.decode("utf-8", "replace") if isinstance(c, bytes) else c for c in r]
                for r in cur.fetchall()]
        con.close()
        return jsonify({"dialect": "mysql", "query": sql, "rows": rows})
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------
# 05.4 PostgreSQL - real postgres:16 (non-superuser webapp role)
# --------------------------------------------------------------------------

@app.route("/pg/label")
def pg_label():
    t = request.args.get("text", "")
    sql = f"SELECT 'Label: ' || '{t}' AS label"  # VULNERABLE (|| concatenation context)
    try:
        con = _pg_conn()
        cur = con.cursor()
        cur.execute(sql)
        rows = _rows(cur)
        con.close()
        return jsonify({"dialect": "postgresql", "query": sql, "rows": rows})
    except Exception as e:
        return _err(e)


@app.route("/pg/items")
def pg_items():
    name = request.args.get("name", "")
    sql = f"SELECT id,name FROM items WHERE name='{name}'"  # VULNERABLE
    try:
        con = _pg_conn()
        cur = con.cursor()
        cur.execute(sql)
        rows = _rows(cur)
        con.close()
        return jsonify({"dialect": "postgresql", "query": sql, "rows": rows})
    except Exception as e:
        return _err(e)


@app.route("/pg/slow")
def pg_slow():
    pid = request.args.get("id", "1")
    sql = f"SELECT id,name FROM items WHERE id={pid}"  # VULNERABLE (time-based pg_sleep)
    try:
        con = _pg_conn()
        cur = con.cursor()
        start = time.time()
        cur.execute(sql)
        rows = _rows(cur)
        elapsed = time.time() - start
        con.close()
        return jsonify({"dialect": "postgresql", "query": sql, "rows": rows,
                        "elapsed_seconds": round(elapsed, 3)})
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------
# 05.1 Oracle - mod_plsql / ORDS-style PL/SQL Gateway facade.
# The Oracle engine is substituted by PostgreSQL (see manifest degraded note);
# the gateway URL shape, DAD routing, anonymous-block generation and the
# dynamic-SQL injection inside the package body are faithful to the WSTG doc.
# --------------------------------------------------------------------------

PLSQL_PACKAGES = {
    "WEB_USERS": {
        "show": {
            "params": ["p_id"],
            # package body builds dynamic SQL by concatenation (the weakness)
            "body": "SELECT user_id, username, email FROM web_users WHERE user_id = {p_id}",
        },
        "find": {
            "params": ["p_name"],
            "body": "SELECT user_id, username, email FROM web_users WHERE username = '{p_name}'",
        },
    },
}


@app.route("/pls/<dad>/<call>")
def plsql_gateway(dad, call):
    if dad != "lab":
        return jsonify({"error": "DAD not found", "dad": dad}), 404
    if "." not in call:
        return jsonify({"error": "expected <package>.<procedure>"}), 404
    pkg, proc = call.split(".", 1)
    spec = PLSQL_PACKAGES.get(pkg, {}).get(proc)
    if not spec:
        return jsonify({"error": "procedure not found", "call": call}), 404
    values = {p: request.args.get(p, "") for p in spec["params"]}
    block = "BEGIN " + pkg + "." + proc + "(" + ", ".join(
        f"{p} => '{values[p]}'" for p in spec["params"]) + "); END;"
    dynamic_sql = spec["body"]
    for p, v in values.items():
        dynamic_sql = dynamic_sql.replace("{" + p + "}", v)  # VULNERABLE concatenation
    try:
        con = _pg_conn()
        cur = con.cursor()
        cur.execute(dynamic_sql)
        rows = _rows(cur)
        con.close()
        return jsonify({"dialect": "oracle-plsql-gateway (PG engine substitute)",
                        "dad": dad, "call": call, "plsql_block": block,
                        "dynamic_sql": dynamic_sql, "rows": rows})
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------
# 05.3 SQL Server - real MSSQL 2022 (linux/amd64 emulation on arm64)
# --------------------------------------------------------------------------

@app.route("/mssql/products")
def mssql_products():
    if not MSSQL_HOST:
        return jsonify({"error": "mssql service not deployed"}), 503
    pid = request.args.get("id", "1")
    sql = f"SELECT id,name,price FROM products WHERE id={pid}"  # VULNERABLE
    try:
        con = _mssql_conn()
        cur = con.cursor()
        cur.execute(sql)
        rows = _rows(cur)
        con.close()
        return jsonify({"dialect": "mssql", "query": sql, "rows": rows})
    except Exception as e:
        return _err(e)


@app.route("/mssql/stacked")
def mssql_stacked():
    if not MSSQL_HOST:
        return jsonify({"error": "mssql service not deployed"}), 503
    pid = request.args.get("id", "1")
    sql = f"SELECT id,name FROM products WHERE id={pid}"  # VULNERABLE (batched queries)
    try:
        con = _mssql_conn()
        cur = con.cursor()
        cur.execute(sql)
        sets = []
        while True:
            if cur.description:
                sets.append(_rows(cur))
            if not cur.nextset():
                break
        con.close()
        return jsonify({"dialect": "mssql", "query": sql, "result_sets": sets})
    except Exception as e:
        return _err(e)


@app.route("/mssql/slow")
def mssql_slow():
    if not MSSQL_HOST:
        return jsonify({"error": "mssql service not deployed"}), 503
    pid = request.args.get("id", "1")
    sql = f"SELECT id,name FROM products WHERE id={pid}"  # VULNERABLE (WAITFOR DELAY)
    try:
        con = _mssql_conn()
        cur = con.cursor()
        start = time.time()
        cur.execute(sql)
        sets = []
        while True:
            if cur.description:
                sets.append(_rows(cur))
            if not cur.nextset():
                break
        elapsed = time.time() - start
        con.close()
        return jsonify({"dialect": "mssql", "query": sql, "result_sets": sets,
                        "elapsed_seconds": round(elapsed, 3)})
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------
# 05.5 MS Access - Jet-dialect facade over SQLite (no Linux Jet/ACE engine).
# Supports IIF(), TOP n, '*'/'?' LIKE wildcards, #date# literals, MID() and
# ';'-separated stacked queries, exactly like the Jet OLEDB surface.
# --------------------------------------------------------------------------

def _jet_split(sql):
    stmts, cur, inq = [], "", False
    for ch in sql:
        if ch == "'":
            inq = not inq
        if ch == ";" and not inq:
            stmts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        stmts.append(cur)
    return [s.strip() for s in stmts if s.strip()]


def _jet_translate(sql):
    limit = None
    m = re.search(r"\bSELECT\s+TOP\s+(\d+)\b", sql, re.I)
    if m:
        limit = int(m.group(1))
        sql = re.sub(r"\bTOP\s+\d+\s*", "", sql, count=1, flags=re.I)
    sql = re.sub(r"#([^#]*)#", r"'\1'", sql)                      # #date# literals
    sql = re.sub(r"\bMID\(", "SUBSTR(", sql, flags=re.I)          # MID -> SUBSTR
    sql = re.sub(r"LIKE\s+'([^']*)'",
                 lambda m: "LIKE '" + m.group(1).replace("*", "%").replace("?", "_") + "'",
                 sql, flags=re.I)                                 # Access wildcards
    if limit is not None:
        sql += f" LIMIT {limit}"
    return sql


@app.route("/access/products")
def access_products():
    name = request.args.get("name", "")
    jet_sql = f"SELECT * FROM products WHERE name LIKE '*{name}*'"  # VULNERABLE
    try:
        con = sqlite3.connect(ACCESS_DB)
        results = []
        for stmt in _jet_split(jet_sql):  # stacked queries, Jet-style
            translated = _jet_translate(stmt)
            cur = con.execute(translated)
            results.append({"jet_statement": stmt, "engine_statement": translated,
                            "rows": [list(r) for r in cur.fetchall()]})
        con.close()
        return jsonify({"dialect": "ms-access-jet-facade (SQLite engine)",
                        "query": jet_sql, "statements": results})
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------
# 05.6 NoSQL - real mongo:7 ($where JS injection + operator injection)
# --------------------------------------------------------------------------

def _nested_qs(qs):
    """PHP/qs-style bracket notation: user[$gt]=x -> {'user': {'$gt': 'x'}}."""
    out = {}
    for pair in qs.split("&"):
        if not pair:
            continue
        k, _, v = pair.partition("=")
        k = urllib.parse.unquote_plus(k)
        v = urllib.parse.unquote_plus(v)
        m = re.match(r"^([^\[]+)((?:\[[^\]]*\])*)$", k)
        if not m:
            out[k] = v
            continue
        base, brackets = m.group(1), re.findall(r"\[([^\]]*)\]", m.group(2))
        if not brackets:
            out[base] = v
            continue
        cur = out.setdefault(base, {})
        for i, bk in enumerate(brackets):
            if i == len(brackets) - 1:
                cur[bk] = v
            else:
                cur = cur.setdefault(bk, {})
    return out


def _nosql_login(u, p):
    filt = {"user": u, "pass": p}  # VULNERABLE: operator dicts pass straight through
    doc = _mongo().users.find_one(filt)
    if doc:
        doc.pop("_id", None)
        return jsonify({"authenticated": True, "filter": repr(filt), "user": doc})
    return jsonify({"authenticated": False, "filter": repr(filt)}), 401


@app.route("/nosql/login", methods=["GET", "POST"])
def nosql_login():
    try:
        if request.method == "POST":
            body = request.get_json(force=True, silent=True) or {}
            u, p = body.get("user", ""), body.get("pass", "")
        else:
            args = _nested_qs(request.query_string.decode())
            u, p = args.get("user", ""), args.get("pass", "")
        return _nosql_login(u, p)
    except Exception as e:
        return _err(e)


@app.route("/nosql/where")
def nosql_where():
    q = request.args.get("q", "")
    where = f"this.name == '{q}'"  # VULNERABLE: server-side JS concatenation
    try:
        docs = list(_mongo().staff.find({"$where": where}))
        for d in docs:
            d.pop("_id", None)
        return jsonify({"dialect": "mongodb", "$where": where, "count": len(docs), "docs": docs})
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------
# 05.7 ORM - SQLAlchemy: user input reaches filter(text(...)) / order_by(text(...))
# --------------------------------------------------------------------------

Base = declarative_base()


class OrmUser(Base):
    __tablename__ = "orm_users"
    id = Column(Integer, primary_key=True)
    username = Column(String)
    role = Column(String)


_engine = None


def _orm_session():
    global _engine
    if _engine is None:
        _engine = create_engine(
            f"postgresql+psycopg2://webapp:webapppass@{PG_HOST}:5432/ormdb")
    return sessionmaker(bind=_engine)()


@app.route("/orm/users")
def orm_users():
    name = request.args.get("name")
    sort = request.args.get("sort")
    try:
        s = _orm_session()
        q = s.query(OrmUser)
        fragments = []
        if name is not None:
            frag = f"username = '{name}'"  # VULNERABLE: RawSQL-style filter fragment
            q = q.filter(text(frag))
            fragments.append(frag)
        if sort:
            q = q.order_by(text(sort))  # VULNERABLE: ORDER BY fragment
            fragments.append(f"ORDER BY {sort}")
        rows = [{"id": u.id, "username": u.username, "role": u.role} for u in q.all()]
        s.close()
        return jsonify({"dialect": "sqlalchemy-orm/postgresql", "fragments": fragments,
                        "rows": rows})
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------
# 05.8 Client-side SQL - alasql in the browser (see static/clientsql.js)
# --------------------------------------------------------------------------

@app.route("/clientsql/")
@app.route("/clientsql")
def clientsql_page():
    return send_from_directory(app.static_folder, "clientsql.html")


@app.route("/clientsql/sink", methods=["GET", "POST"])
def clientsql_sink():
    if request.method == "POST":
        rep = request.get_json(force=True, silent=True) or {}
        token = str(rep.get("token", "default"))
        SINKS[token] = {"sql": rep.get("sql"), "rows": rep.get("rows"),
                        "received_at": time.time()}
        return jsonify({"stored": True, "token": token})
    token = request.args.get("token", "default")
    return jsonify(SINKS.get(token, {}))


# --------------------------------------------------------------------------
# INJT-06 LDAP - real OpenLDAP, concatenated search filter
# --------------------------------------------------------------------------

def _lenient_filter(filt):
    """Naive-client filter handling: everything after the first complete
    filter element is ignored (lenient parsers accept the classic
    '*)...(|(uid=*' injection garbage). The server still evaluates a real
    LDAP filter built by concatenation."""
    depth = 0
    for i, ch in enumerate(filt):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return filt[:i + 1]
    return filt


@app.route("/ldap/login")
def ldap_login():
    uid = request.args.get("uid", "")
    pw = request.args.get("password", "")
    filt = f"(&(uid={uid})(userPassword={pw}))"  # VULNERABLE concatenation
    sent = _lenient_filter(filt)
    try:
        conn = _ldap_conn()
        ok = conn.search(f"ou=people,{LDAP_BASE}", sent,
                         attributes=["uid", "cn", "mail", "description", "userPassword"])
        entries = [{"dn": e.entry_dn, "attributes": e.entry_attributes_as_dict}
                   for e in conn.entries]
        conn.unbind()
        return jsonify({"dialect": "openldap", "filter": filt, "filter_sent": sent,
                        "search_ok": ok, "count": len(entries), "entries": entries,
                        "authenticated": len(entries) > 0})
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------
# INJT-07 XML - tag injection into an order envelope + XXE-flavoured parse
# --------------------------------------------------------------------------

@app.route("/xml/order", methods=["POST"])
def xml_order():
    item = request.form.get("item", "")
    price = request.form.get("price", "0")
    qty = request.form.get("qty", "1")
    envelope = (f"<order><user>guest</user><item>{item}</item>"
                f"<price>{price}</price><qty>{qty}</qty></order>")  # VULNERABLE
    try:
        root = etree.fromstring(envelope.encode())
        prices = [p.text for p in root.findall(".//price")]
        unit = float(prices[0])  # business logic trusts the FIRST price element
        total = unit * float(qty)
        return jsonify({"envelope": envelope, "prices_seen": prices,
                        "unit_price": unit, "total": total})
    except Exception as e:
        return jsonify({"envelope": envelope, "error": str(e)}), 400


@app.route("/xml/parse", methods=["POST"])
def xml_parse():
    body = request.get_data()
    # VULNERABLE: external entities resolved (file:// only; no_network=True
    # keeps this in-range - no outbound calls).
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=True)
    try:
        root = etree.fromstring(body, parser)
        text_out = "".join(root.itertext())
        return jsonify({"root_tag": root.tag, "text": text_out})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# --------------------------------------------------------------------------
# INJT-09 XPath - concatenated XPath authentication
# --------------------------------------------------------------------------

@app.route("/xpath/login")
def xpath_login():
    u = request.args.get("user", "")
    p = request.args.get("pass", "")
    xp = f"//user[login/text()='{u}' and password/text()='{p}']"  # VULNERABLE
    try:
        tree = etree.parse(os.path.join(os.path.dirname(__file__), "data", "users.xml"))
        nodes = tree.xpath(xp)
        users = [{"login": n.findtext("login"), "role": n.findtext("role"),
                  "secret": n.findtext("secret")} for n in nodes]
        if users:
            return jsonify({"authenticated": True, "xpath": xp,
                            "matched": len(users), "users": users})
        return jsonify({"authenticated": False, "xpath": xp, "matched": 0}), 401
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------
# INJT-26 JSON parser differential - backend half (last-wins json.loads).
# The front half (first-wins validator/proxy) is the jsonfront service :8401.
# --------------------------------------------------------------------------

@app.route("/json/backend", methods=["POST"])
def json_backend():
    if request.headers.get("X-From-Front") != "jsonfront":
        return jsonify({"error": "direct backend access forbidden"}), 403
    raw = request.get_data()
    try:
        doc = json.loads(raw)  # standard parser: duplicate keys -> LAST wins
    except Exception as e:
        return jsonify({"stage": "backend", "error": str(e)}), 400
    role = doc.get("role")
    if doc.get("action") == "read_secret" and role == "admin":
        return jsonify({"stage": "backend", "seen_role": role,
                        "secret": JSON_SECRET, "granted": True})
    return jsonify({"stage": "backend", "seen_role": role, "granted": False}), 403


# --------------------------------------------------------------------------

if __name__ == "__main__":
    seed_access()
    seed_ldap()
    seed_mssql()
    app.run(host="0.0.0.0", port=5000, threaded=True)