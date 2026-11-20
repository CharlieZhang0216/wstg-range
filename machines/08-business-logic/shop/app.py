"""AcmeShop - intentionally vulnerable e-commerce app for WSTG-BUSL-01..11.

AUTHORISED SECURITY TRAINING TARGET. Every business-logic flaw below is deliberate.
Do not deploy this code anywhere real.
"""
import hashlib
import hmac
import io
import json
import os
import time
import uuid
import zipfile
from datetime import datetime, timezone
from decimal import Decimal

import psycopg2
import psycopg2.extras
import requests
from flask import Flask, g, jsonify, request, session

app = Flask(__name__)
app.secret_key = "m08-shop-session-key"

DB_HOST = os.environ.get("DB_HOST", "db")
PAY_URL = os.environ.get("PAY_URL", "http://pay:5000")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/srv/uploads")

# WSTG-BUSL-03: hardcoded HMAC key, also leaked to the client in /static/checkout.js.
# Worse: the "integrity" signature is computed over the order id ONLY, never over
# the line items or the total, so a paid order can be rewritten freely.
INTEGRITY_KEY = b"hardcoded-hmac-key-123"

FLASH_START = datetime(2025, 1, 1, tzinfo=timezone.utc)
FLASH_END = datetime(2025, 1, 2, tzinfo=timezone.utc)


def db():
    if "db" not in g:
        g.db = psycopg2.connect(host=DB_HOST, user="shop", password="ShopPW123!", dbname="shop")
        g.db.autocommit = True
    return g.db


@app.teardown_appcontext
def close_db(exc):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def q(sql, args=(), one=False):
    cur = db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(sql, args)
    rows = cur.fetchall() if cur.description else []
    cur.close()
    return (rows[0] if rows else None) if one else rows


def x(sql, args=()):
    cur = db().cursor()
    cur.execute(sql, args)
    cur.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id SERIAL PRIMARY KEY, username TEXT UNIQUE, password TEXT, balance NUMERIC(12,2));
CREATE TABLE IF NOT EXISTS products(
  id SERIAL PRIMARY KEY, sku TEXT, name TEXT, price NUMERIC(12,2), stock INT,
  reserved INT DEFAULT 0, flash_price NUMERIC(12,2));
CREATE TABLE IF NOT EXISTS coupons(
  code TEXT PRIMARY KEY, kind TEXT, value NUMERIC(12,2), max_uses INT, uses INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS redemptions(
  id SERIAL PRIMARY KEY, code TEXT, user_id INT, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS cart_items(
  id SERIAL PRIMARY KEY, user_id INT, product_id INT, quantity BIGINT);
CREATE TABLE IF NOT EXISTS orders(
  id SERIAL PRIMARY KEY, user_id INT, status TEXT DEFAULT 'pending',
  total NUMERIC(14,2), shipping NUMERIC(12,2) DEFAULT 0, discount NUMERIC(12,2) DEFAULT 0,
  currency TEXT DEFAULT 'USD', integrity TEXT, paid_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS order_items(
  id SERIAL PRIMARY KEY, order_id INT, product_id INT, name TEXT,
  quantity BIGINT, unit_price NUMERIC(14,2));
CREATE TABLE IF NOT EXISTS reservations(
  id SERIAL PRIMARY KEY, user_id INT, product_id INT, quantity INT,
  expires_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS gift_cards(
  code TEXT PRIMARY KEY, value NUMERIC(12,2), redeemed_by INT);
CREATE TABLE IF NOT EXISTS fulfilments(
  id SERIAL PRIMARY KEY, order_id INT, status TEXT, created_at TIMESTAMPTZ DEFAULT now());
"""


def seed():
    for stmt in SCHEMA.strip().split(";"):
        if stmt.strip():
            x(stmt)
    x("TRUNCATE users, products, coupons, redemptions, cart_items, orders, "
      "order_items, reservations, gift_cards, fulfilments RESTART IDENTITY CASCADE")
    x("INSERT INTO users(username,password,balance) VALUES "
      "('alice','Password123!',100.00),('bob','Password123!',100.00)")
    x("INSERT INTO products(sku,name,price,stock,reserved,flash_price) VALUES "
      "('WIDGET-01','Widget',10.00,100,0,NULL),"
      "('GADGET-01','Gadget Pro',500.00,10,0,NULL),"
      "('SNEAKER-01','Limited Sneaker',120.00,3,0,NULL),"
      "('FLASH-01','Flash Deal TV',999.00,50,0,9.99)")
    # ONCE50: globally single-use voucher (WSTG-BUSL-04 race target)
    # WELCOME5: "one per customer" promo (WSTG-BUSL-05, enforced per-session only)
    x("INSERT INTO coupons(code,kind,value,max_uses,uses) VALUES "
      "('SAVE10','percent',10,NULL,0),"
      "('ONCE50','flat',50.00,1,0),"
      "('WELCOME5','flat',5.00,NULL,0)")
    # WSTG-BUSL-07: guessable gift-card code in a small enumerable space.
    x("INSERT INTO gift_cards(code,value) VALUES ('GC-1234',50.00)")
    # clear uploaded files so runs are idempotent
    if os.path.isdir(UPLOAD_DIR):
        for root, dirs, files in os.walk(UPLOAD_DIR, topdown=False):
            for f in files:
                try:
                    os.remove(os.path.join(root, f))
                except OSError:
                    pass
            for d in dirs:
                try:
                    os.rmdir(os.path.join(root, d))
                except OSError:
                    pass


@app.before_request
def ensure_schema():
    if not getattr(app, "_seeded", False):
        seed()
        app._seeded = True


def current_user():
    uid = session.get("uid")
    return q("SELECT * FROM users WHERE id=%s", (uid,), one=True) if uid else None


def money(v):
    return float(v) if v is not None else None


# ---------------------------------------------------------------- basic pages

@app.get("/")
def home():
    return """<!doctype html><title>AcmeShop</title><h1>AcmeShop</h1>
<p>Intentionally vulnerable business-logic training target (WSTG-BUSL).</p>
<ul>
<li><a href="/products">Products</a></li>
<li><a href="/static/checkout.js">checkout.js</a></li>
</ul>
<!-- avatar upload form: client-side restriction only (WSTG-BUSL-08) -->
<form action="/account/avatar" method="post" enctype="multipart/form-data">
  <input type="file" name="file" accept=".jpg,.jpeg,.png">
  <button>Upload avatar</button>
</form>
<script>
// client-side "security": only jpg/png allowed! (server does not re-check)
document.querySelector('input[type=file]').addEventListener('change', function(e){
  if(!/\\.(jpg|jpeg|png)$/i.test(e.target.value)) alert('Only JPG/PNG images allowed');
});
</script>
"""


@app.get("/health")
def health():
    q("SELECT 1", one=True)
    return jsonify(ok=True)


@app.get("/static/checkout.js")
def checkout_js():
    # WSTG-BUSL-03: the integrity key ships to the browser, and the signature
    # covers only the order id - never the amounts it is supposed to protect.
    js = (
        "// AcmeShop checkout helper\n"
        "const INTEGRITY_KEY = 'hardcoded-hmac-key-123'; // TODO: move server-side\n"
        "async function signOrder(orderId){\n"
        "  const enc = new TextEncoder();\n"
        "  const key = await crypto.subtle.importKey('raw', enc.encode(INTEGRITY_KEY),\n"
        "    {name:'HMAC',hash:'SHA-256'}, false, ['sign']);\n"
        "  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(String(orderId)));\n"
        "  return [...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,'0')).join('');\n"
        "}\n"
    )
    return app.response_class(js, mimetype="application/javascript")


@app.post("/register")
def register():
    d = request.get_json(force=True)
    try:
        x("INSERT INTO users(username,password,balance) VALUES (%s,%s,100.00)",
          (d["username"], d.get("password", "Password123!")))
    except psycopg2.errors.UniqueViolation:
        return jsonify(error="exists"), 409
    u = q("SELECT * FROM users WHERE username=%s", (d["username"],), one=True)
    session["uid"] = u["id"]
    return jsonify(user_id=u["id"], username=u["username"], balance=money(u["balance"]))


@app.post("/login")
def login():
    d = request.get_json(force=True)
    u = q("SELECT * FROM users WHERE username=%s AND password=%s",
          (d.get("username"), d.get("password")), one=True)
    if not u:
        return jsonify(error="bad credentials"), 401
    session["uid"] = u["id"]
    return jsonify(user_id=u["id"], balance=money(u["balance"]))


@app.post("/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/products")
def products():
    rows = q("SELECT * FROM products ORDER BY id")
    out = []
    for p in rows:
        out.append(dict(id=p["id"], sku=p["sku"], name=p["name"], price=money(p["price"]),
                        stock=p["stock"], reserved=p["reserved"],
                        available=p["stock"] - p["reserved"],
                        flash_price=money(p["flash_price"])))
    return jsonify(products=out)


# ---------------------------------------------------------------- cart

@app.get("/cart")
def cart_view():
    u = current_user()
    if not u:
        return jsonify(error="login required"), 401
    items = q("SELECT c.*, p.name, p.price FROM cart_items c JOIN products p ON p.id=c.product_id "
              "WHERE c.user_id=%s", (u["id"],))
    total = sum(Decimal(str(i["price"])) * i["quantity"] for i in items) if items else Decimal(0)
    return jsonify(items=[dict(product_id=i["product_id"], name=i["name"],
                               quantity=i["quantity"], unit_price=money(i["price"])) for i in items],
                   total=float(total))


@app.post("/cart/add")
def cart_add():
    """WSTG-BUSL-01: no server-side validation of quantity (negative, zero,
    above stock, absurd magnitudes all accepted).
    WSTG-BUSL-11: adding to cart immediately reserves stock, forever."""
    u = current_user()
    if not u:
        return jsonify(error="login required"), 401
    d = request.get_json(force=True)
    pid, qty = int(d["product_id"]), int(d["quantity"])
    p = q("SELECT * FROM products WHERE id=%s", (pid,), one=True)
    if not p:
        return jsonify(error="no such product"), 404
    # BUG: no check that 0 < qty <= available. Negative quantities create credit.
    x("INSERT INTO cart_items(user_id,product_id,quantity) VALUES (%s,%s,%s)", (u["id"], pid, qty))
    # BUG: reservation has no expiry and no per-user cap (denial of inventory).
    x("INSERT INTO reservations(user_id,product_id,quantity,expires_at) VALUES (%s,%s,%s,NULL)",
      (u["id"], pid, qty))
    x("UPDATE products SET reserved = reserved + %s WHERE id=%s", (qty, pid))
    return jsonify(ok=True, product_id=pid, quantity=qty,
                   line_total=float(Decimal(str(p["price"])) * qty))


@app.post("/cart/clear")
def cart_clear():
    u = current_user()
    if not u:
        return jsonify(error="login required"), 401
    x("DELETE FROM cart_items WHERE user_id=%s", (u["id"],))
    return jsonify(ok=True)


@app.post("/cart/coupon")
def cart_coupon():
    u = current_user()
    if not u:
        return jsonify(error="login required"), 401
    code = request.get_json(force=True).get("code", "")
    c = q("SELECT * FROM coupons WHERE code=%s", (code,), one=True)
    if not c:
        return jsonify(error="unknown code"), 404
    if code == "WELCOME5":
        # WSTG-BUSL-05: "one per customer" enforced in the SESSION, not per account.
        if session.get("welcome_used"):
            return jsonify(error="already used in this session"), 400
        session["welcome_used"] = True
    if c["max_uses"] is not None:
        # WSTG-BUSL-04: classic TOCTOU. Check-then-act with a wide window and no
        # row lock / atomic conditional update, so parallel requests all pass.
        if c["uses"] >= c["max_uses"]:
            return jsonify(error="coupon exhausted"), 400
        time.sleep(0.4)  # simulated payment/fraud check latency
        x("UPDATE coupons SET uses = uses + 1 WHERE code=%s", (code,))
    x("INSERT INTO redemptions(code,user_id) VALUES (%s,%s)", (code, u["id"]))
    session["coupon"] = code
    return jsonify(ok=True, code=code, kind=c["kind"], value=money(c["value"]))


# ---------------------------------------------------------------- checkout

def order_json(o):
    items = q("SELECT * FROM order_items WHERE order_id=%s", (o["id"],))
    return dict(order_id=o["id"], user_id=o["user_id"], status=o["status"],
                total=money(o["total"]), shipping=money(o["shipping"]),
                discount=money(o["discount"]), currency=o["currency"],
                integrity=o["integrity"], paid_at=str(o["paid_at"]) if o["paid_at"] else None,
                items=[dict(product_id=i["product_id"], name=i["name"],
                            quantity=i["quantity"], unit_price=money(i["unit_price"])) for i in items])


@app.post("/checkout")
def checkout():
    """Creates an order from the cart.

    WSTG-BUSL-02: unit_price / shipping / total supplied by the client are trusted.
    WSTG-BUSL-04: the flash-sale window is evaluated against a CLIENT-supplied
    purchase_time instead of the server clock.
    """
    u = current_user()
    if not u:
        return jsonify(error="login required"), 401
    d = request.get_json(force=True) if request.data else {}
    client_lines = {int(l["product_id"]): l for l in d.get("lines", [])}
    cart = q("SELECT * FROM cart_items WHERE user_id=%s", (u["id"],))
    if not cart and not client_lines:
        return jsonify(error="empty cart"), 400

    purchase_time = None
    if d.get("purchase_time"):
        try:
            purchase_time = datetime.fromisoformat(d["purchase_time"]).replace(tzinfo=timezone.utc)
        except ValueError:
            purchase_time = None

    lines, subtotal = [], Decimal(0)
    src = cart or [dict(product_id=pid, quantity=int(l.get("quantity", 1)))
                   for pid, l in client_lines.items()]
    for item in src:
        p = q("SELECT * FROM products WHERE id=%s", (item["product_id"],), one=True)
        if not p:
            continue
        qty = int(item["quantity"])
        # The ONLY stock enforcement point in the app: checkout rejects lines
        # exceeding available stock. Cart-add reservations (which never expire)
        # therefore let an attacker lock legitimate buyers out (WSTG-BUSL-11).
        if qty > p["stock"] - p["reserved"]:
            return jsonify(error="insufficient stock", product_id=p["id"],
                           available=p["stock"] - p["reserved"]), 409
        price = Decimal(str(p["price"]))
        # BUG (BUSL-04): flash price decided by client-supplied timestamp; the
        # server never checks that 'now' is inside the sale window.
        if p["flash_price"] is not None and purchase_time and FLASH_START <= purchase_time <= FLASH_END:
            price = Decimal(str(p["flash_price"]))
        # BUG (BUSL-02): client-supplied unit_price overrides the catalogue price.
        cl = client_lines.get(p["id"])
        if cl and cl.get("unit_price") is not None:
            price = Decimal(str(cl["unit_price"]))
        lines.append((p["id"], p["name"], qty, price))
        subtotal += price * qty

    discount = Decimal(0)
    code = session.get("coupon")
    if code:
        c = q("SELECT * FROM coupons WHERE code=%s", (code,), one=True)
        if c:
            discount = subtotal * Decimal(str(c["value"])) / 100 if c["kind"] == "percent" \
                else Decimal(str(c["value"]))
    shipping = Decimal(str(d.get("shipping", 5.00)))  # BUG (BUSL-02): client-set shipping
    computed = subtotal - discount + shipping
    # BUG (BUSL-02): client-supplied grand total wins over the computed one.
    total = Decimal(str(d["total"])) if d.get("total") is not None else computed

    cur = db().cursor()
    cur.execute("INSERT INTO orders(user_id,total,shipping,discount) VALUES (%s,%s,%s,%s) RETURNING id",
                (u["id"], total, shipping, discount))
    oid = cur.fetchone()[0]
    cur.close()
    for pid, name, qty, price in lines:
        x("INSERT INTO order_items(order_id,product_id,name,quantity,unit_price) VALUES (%s,%s,%s,%s,%s)",
          (oid, pid, name, qty, price))
    # BUG (BUSL-03): integrity signature covers ONLY the order id.
    sig = hmac.new(INTEGRITY_KEY, str(oid).encode(), hashlib.sha256).hexdigest()
    x("UPDATE orders SET integrity=%s WHERE id=%s", (sig, oid))
    x("DELETE FROM cart_items WHERE user_id=%s", (u["id"],))
    session.pop("coupon", None)
    o = q("SELECT * FROM orders WHERE id=%s", (oid,), one=True)
    return jsonify(order_json(o)), 201


@app.get("/order/<int:oid>")
def order_get(oid):
    o = q("SELECT * FROM orders WHERE id=%s", (oid,), one=True)
    if not o:
        return jsonify(error="no such order"), 404
    return jsonify(order_json(o))


@app.post("/order/update")
def order_update():
    """WSTG-BUSL-03: 'integrity-protected' post-payment order edit. The HMAC is
    verified, but it only covers the order id, so line items and total can be
    rewritten after payment while the signature stays valid."""
    d = request.get_json(force=True)
    oid = int(d["order_id"])
    o = q("SELECT * FROM orders WHERE id=%s", (oid,), one=True)
    if not o:
        return jsonify(error="no such order"), 404
    expect = hmac.new(INTEGRITY_KEY, str(oid).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, d.get("integrity", "")):
        return jsonify(error="integrity check failed"), 400
    x("DELETE FROM order_items WHERE order_id=%s", (oid,))
    for l in d.get("lines", []):
        x("INSERT INTO order_items(order_id,product_id,name,quantity,unit_price) VALUES (%s,%s,%s,%s,%s)",
          (oid, int(l["product_id"]), l.get("name", "item"), int(l["quantity"]),
           Decimal(str(l.get("unit_price", 0)))))
    if d.get("total") is not None:
        x("UPDATE orders SET total=%s WHERE id=%s", (Decimal(str(d["total"])), oid))
    return jsonify(ok=True, order=order_json(q("SELECT * FROM orders WHERE id=%s", (oid,), one=True)))


@app.post("/checkout/confirm")
def checkout_confirm():
    """WSTG-BUSL-06: confirmation does not require a completed payment.
    WSTG-BUSL-01: a negative total is 'paid' by crediting the customer."""
    d = request.get_json(force=True)
    oid = int(d["order_id"])
    o = q("SELECT * FROM orders WHERE id=%s", (oid,), one=True)
    if not o:
        return jsonify(error="no such order"), 404
    # BUG: no check of payment state at all.
    if o["total"] <= 0:
        x("UPDATE users SET balance = balance - %s WHERE id=%s", (o["total"], o["user_id"]))
    for i in q("SELECT * FROM order_items WHERE order_id=%s", (oid,)):
        x("UPDATE products SET stock = stock - %s WHERE id=%s", (i["quantity"], i["product_id"]))
    x("UPDATE orders SET status='paid', paid_at=now() WHERE id=%s", (oid,))
    u = q("SELECT * FROM users WHERE id=%s", (o["user_id"],), one=True)
    return jsonify(ok=True, order_id=oid, status="paid", balance=money(u["balance"]))


@app.post("/order/ship")
def order_ship():
    """WSTG-BUSL-06: fulfilment enforces no precondition - unpaid orders (and
    even order ids that do not exist) can be shipped directly."""
    d = request.get_json(force=True)
    oid = int(d["order_id"])
    x("INSERT INTO fulfilments(order_id,status) VALUES (%s,'shipped')", (oid,))
    return jsonify(ok=True, order_id=oid, status="shipped")


@app.post("/order/refund")
def order_refund():
    """WSTG-BUSL-10: refund amount is client-supplied and unvalidated; a negative
    refund credits the attacker's balance instead of debiting it."""
    d = request.get_json(force=True)
    oid = int(d["order_id"])
    amount = Decimal(str(d["amount"]))
    o = q("SELECT * FROM orders WHERE id=%s", (oid,), one=True)
    if not o:
        return jsonify(error="no such order"), 404
    x("UPDATE users SET balance = balance - %s WHERE id=%s", (amount, o["user_id"]))
    u = q("SELECT * FROM users WHERE id=%s", (o["user_id"],), one=True)
    return jsonify(ok=True, refunded=float(amount), balance=money(u["balance"]))


# ---------------------------------------------------------------- payment

@app.post("/payment/create")
def payment_create():
    """WSTG-BUSL-10: the amount sent to the payment provider can be overridden
    by the client, so a 500.00 order can be 'paid' with a 0.01 intent."""
    d = request.get_json(force=True)
    oid = int(d["order_id"])
    o = q("SELECT * FROM orders WHERE id=%s", (oid,), one=True)
    if not o:
        return jsonify(error="no such order"), 404
    amount = Decimal(str(d["amount"])) if d.get("amount") is not None else o["total"]
    r = requests.post(PAY_URL + "/intents",
                      json={"amount": float(amount), "currency": o["currency"], "order_ref": oid},
                      timeout=10)
    return jsonify(r.json()), r.status_code


@app.post("/payment/callback")
def payment_callback():
    """WSTG-BUSL-10: the 'payment succeeded' callback is unauthenticated and
    unverified - no signature, no lookup of the intent, no amount reconciliation.
    Anyone can mark any order paid."""
    d = request.get_json(force=True)
    oid = int(d["order_id"])
    if d.get("status") == "succeeded":
        x("UPDATE orders SET status='paid', paid_at=now() WHERE id=%s", (oid,))
        o = q("SELECT * FROM orders WHERE id=%s", (oid,), one=True)
        if o:
            return jsonify(ok=True, order_id=oid, status="paid")
    return jsonify(error="not processed"), 400


# ---------------------------------------------------------------- gift cards

@app.post("/giftcard/redeem")
def giftcard_redeem():
    """WSTG-BUSL-07: no rate limiting, no lockout, no anomaly detection - the
    whole GC-XXXX space can be enumerated and a found card redeemed instantly."""
    u = current_user()
    if not u:
        return jsonify(error="login required"), 401
    code = request.get_json(force=True).get("code", "")
    gc = q("SELECT * FROM gift_cards WHERE code=%s", (code,), one=True)
    if not gc:
        return jsonify(valid=False, code=code), 404
    if gc["redeemed_by"]:
        return jsonify(valid=True, redeemed=True), 400
    x("UPDATE gift_cards SET redeemed_by=%s WHERE code=%s", (u["id"], code))
    x("UPDATE users SET balance = balance + %s WHERE id=%s", (gc["value"], u["id"]))
    return jsonify(valid=True, redeemed=True, value=money(gc["value"]))


# ---------------------------------------------------------------- uploads

@app.post("/account/avatar")
def avatar_upload():
    """WSTG-BUSL-08: extension blacklist is lowercase-suffix only and the
    declared Content-Type is trusted. .html/.svg/.php and double extensions
    (x.php.jpg) are stored verbatim in the web-served uploads volume.
    WSTG-BUSL-09: file CONTENT is never inspected (script-bearing SVG accepted)."""
    f = request.files.get("file")
    if not f:
        return jsonify(error="no file"), 400
    name = os.path.basename(f.filename or "upload.bin")
    if name.lower().endswith((".exe", ".sh")):  # the entire "validation"
        return jsonify(error="file type not allowed"), 400
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    dest = os.path.join(UPLOAD_DIR, name)
    f.save(dest)
    return jsonify(ok=True, stored=name, url=f"/uploads/{name}",
                   declared_type=f.mimetype), 201


@app.post("/products/import")
def products_import():
    """WSTG-BUSL-09: bulk product-image import extracts zip entries by joining
    the raw entry name onto the target dir - classic zip-slip. '../../' entries
    escape the import directory (and are then served/executed by the media host)."""
    f = request.files.get("file")
    if not f:
        return jsonify(error="no file"), 400
    import_id = uuid.uuid4().hex[:12]
    dest = os.path.join(UPLOAD_DIR, "imports", import_id)
    os.makedirs(dest, exist_ok=True)
    zf = zipfile.ZipFile(io.BytesIO(f.read()))
    extracted = []
    for entry in zf.namelist():
        target = os.path.join(dest, entry)  # BUG: no containment check
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as out:
            out.write(zf.read(entry))
        extracted.append(entry)
    return jsonify(ok=True, import_id=import_id, dir=f"/uploads/imports/{import_id}/",
                   extracted=extracted), 201


# ---------------------------------------------------------------- lab helpers

@app.get("/lab/state")
def lab_state():
    return jsonify(
        users=[dict(id=u["id"], username=u["username"], balance=money(u["balance"]))
               for u in q("SELECT * FROM users ORDER BY id")],
        products=[dict(id=p["id"], sku=p["sku"], price=money(p["price"]), stock=p["stock"],
                       reserved=p["reserved"], available=p["stock"] - p["reserved"])
                  for p in q("SELECT * FROM products ORDER BY id")],
        coupons=[dict(code=c["code"], max_uses=c["max_uses"], uses=c["uses"])
                 for c in q("SELECT * FROM coupons ORDER BY code")],
        redemptions=[dict(code=r["code"], user_id=r["user_id"])
                     for r in q("SELECT * FROM redemptions ORDER BY id")],
        reservations=[dict(id=r["id"], user_id=r["user_id"], product_id=r["product_id"],
                           quantity=r["quantity"],
                           expires_at=str(r["expires_at"]) if r["expires_at"] else None)
                      for r in q("SELECT * FROM reservations ORDER BY id")],
        fulfilments=[dict(order_id=f["order_id"], status=f["status"])
                     for f in q("SELECT * FROM fulfilments ORDER BY id")],
        gift_cards=[dict(code=g["code"], redeemed_by=g["redeemed_by"])
                    for g in q("SELECT * FROM gift_cards ORDER BY code")],
        server_time=datetime.now(timezone.utc).isoformat(),
        flash_window=[FLASH_START.isoformat(), FLASH_END.isoformat()],
    )


@app.post("/lab/reset")
def lab_reset():
    seed()
    session.clear()
    return jsonify(ok=True, reset=True)


@app.post("/lab/sweep")
def lab_sweep():
    """Simulated reservation-expiry cron. Reservations are created with
    expires_at=NULL and the sweep only releases rows whose expiry has passed,
    so it never releases anything (WSTG-BUSL-11)."""
    rows = q("SELECT * FROM reservations WHERE expires_at IS NOT NULL AND expires_at < now()")
    released = 0
    for r in rows:
        x("UPDATE products SET reserved = reserved - %s WHERE id=%s", (r["quantity"], r["product_id"]))
        x("DELETE FROM reservations WHERE id=%s", (r["id"],))
        released += 1
    return jsonify(ok=True, released=released)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)