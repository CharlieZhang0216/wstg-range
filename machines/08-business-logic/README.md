# Machine 08 — Business Logic (WSTG-BUSL-01 … WSTG-BUSL-11)

> **WARNING — intentionally vulnerable training target.**
> This machine is a deliberately broken e-commerce application for **authorised
> security testing / training only**. Every flaw described below is intentional.
> Run it only on an isolated lab host, never expose it to untrusted networks,
> and never reuse any of this code in a real system. All data is synthetic and
> the payment provider is an in-range mock — no real PSP is ever contacted.

## What this is

**AcmeShop** — one coherent storefront with a real multi-step purchase flow:

```
browse (/products) → cart (/cart/add) → coupon (/cart/coupon)
  → checkout (/checkout) → payment (/payment/create → mock PSP → /payment/callback)
  → confirmation (/checkout/confirm) → fulfilment (/order/ship)
```

Every WSTG-BUSL test is a flaw **in this flow**: each individual request looks
legitimate; the application logic itself is wrong.

Seed data: users `alice` / `bob` (`Password123!`, balance 100.00 each);
products Widget 10.00 (stock 100), Gadget Pro 500.00 (stock 10), Limited
Sneaker 120.00 (stock 3), Flash Deal TV 999.00 (flash price 9.99, window
**2025-01-01 … 2025-01-02 — long expired**); coupons `SAVE10` (10 %, unlimited),
`ONCE50` (50.00 off, **globally single-use**), `WELCOME5` (5.00 off,
"one per customer"); gift card `GC-1234` (50.00) hidden in the `GC-1000…GC-1999`
space.

## Topology & ports (block 8800–8899, loopback-only)

| Service | Image | Port | Role |
|---|---|---|---|
| shop | python:3.12-slim + Flask/gunicorn | `127.0.0.1:8800` | storefront, cart, checkout, orders, uploads, lab helpers |
| pay | python:3.12-slim + Flask/gunicorn | `127.0.0.1:8810` | **mock** payment provider (intents, test-card charge) |
| media | php:8.3-apache | `127.0.0.1:8820` | serves the shared uploads volume — and executes PHP in it |
| db | postgres:16-alpine | internal only | datastore (`backend` network, `internal: true`) |

`shop` and `media` share the `uploads` named volume (`/srv/uploads` ↔
`/var/www/html`). Compose project `wstg-m08`, containers `wstg-m08-<service>`.

## Run

```bash
cd machines/08-business-logic
docker compose config -q
docker compose up --build -d
```

## Verify (isolated venv)

```bash
python3 -m venv verify/.venv
verify/.venv/bin/pip install -r verify/requirements.txt   # stdlib-only, no deps
verify/.venv/bin/python ../../tools/runner.py machines/08-business-logic
```

All probes reset state first (`POST /lab/reset` + pay `POST /reset`), so the
suite is idempotent — run it two or three times in a row.

Lab helpers: `GET /lab/state` (full DB snapshot), `POST /lab/reset` (reseed +
wipe uploads), `POST /lab/sweep` (the reservation-expiry "cron" — a no-op).

## WSTG coverage & attack walkthroughs

| ID | Test | Severity |
|---|---|---|
| WSTG-BUSL-01 | Business Logic Data Validation | high |
| WSTG-BUSL-02 | Ability to Forge Requests | high |
| WSTG-BUSL-03 | Integrity Checks | high |
| WSTG-BUSL-04 | Process Timing | high |
| WSTG-BUSL-05 | Function-Use Limits | medium |
| WSTG-BUSL-06 | Circumvention of Work Flows | high |
| WSTG-BUSL-07 | Defenses Against Application Misuse | medium |
| WSTG-BUSL-08 | Upload of Unexpected File Types | critical |
| WSTG-BUSL-09 | Upload of Malicious Files | critical |
| WSTG-BUSL-10 | Payment Functionality | critical |
| WSTG-BUSL-11 | Denial of Inventory | medium |

All JSON examples below assume a logged-in session cookie
(`POST /login {"username":"alice","password":"Password123!"}`).

### BUSL-01 — data validation
`/cart/add` never validates quantity. Negative quantity creates credit:
```
POST /cart/add        {"product_id":1,"quantity":-2}     → line_total -20.00
POST /checkout        {"shipping":0}                     → total -20.00
POST /checkout/confirm {"order_id":1}                    → "paid", balance 100 → 120
```
A quantity of `1000000000` against 10 units of stock is also accepted.

### BUSL-02 — forge requests
Checkout trusts the hidden form fields `unit_price`, `shipping`, `total`:
```
POST /cart/add {"product_id":2,"quantity":1}
POST /checkout {"lines":[{"product_id":2,"quantity":1,"unit_price":0.01}],
                "shipping":0,"total":0.01}
```
Pay the 0.01 intent normally → the 500.00 Gadget Pro is yours, order `paid`.

### BUSL-03 — integrity checks
`/static/checkout.js` leaks `INTEGRITY_KEY='hardcoded-hmac-key-123'`, and the
order "integrity" HMAC covers **only the order id**. Pay an order, then:
```
sig = HMAC-SHA256(key, str(order_id))          # still valid after tampering
POST /order/update {"order_id":1,"integrity":sig,"total":0,
  "lines":[{"product_id":2,"quantity":10,"unit_price":0}]}
```
The paid order now contains 10 Gadget Pros for 0.00.

### BUSL-04 — process timing
*Race:* `ONCE50` is check-then-act with a 0.4 s window and no row lock. Two
users applying it **in parallel** (threads) both succeed → `uses=2` on a
`max_uses=1` coupon, two redemptions.
*Time window:* the flash sale ended 2025-01-02, but `/checkout` evaluates the
**client-supplied** `purchase_time`:
```
POST /checkout {"shipping":0,"purchase_time":"2025-01-01T12:00:00"}
```
→ Flash Deal TV at 9.99 instead of 999.00, years after the sale ended.

### BUSL-05 — function-use limits
`WELCOME5` is "one per customer" but the flag lives in the **session**.
Log in as `alice`, redeem; open a fresh cookie jar, log in as `alice` again,
redeem again → two redemptions for the same account.

### BUSL-06 — circumvention of workflows
Skip payment entirely:
```
POST /checkout/confirm {"order_id":1}   → status "paid" (no payment exists)
POST /order/ship       {"order_id":2}   → shipped while order is "pending"
POST /order/ship       {"order_id":999999} → shipped (order does not exist)
```

### BUSL-07 — defenses against misuse
`/giftcard/redeem` has no rate limit, lockout or anomaly detection. Sweep
`GC-1000 … GC-1299` (300 requests): none blocked, `GC-1234` hits, balance
100 → 150.

### BUSL-08 — unexpected file types
The avatar form restricts types **client-side only** (`accept=".jpg,.png"`);
the server blacklists just lowercase `.exe`/`.sh` and trusts Content-Type.
Upload `probe.php.jpg` containing `<?php echo 'PWNED-'.(6*7); ?>` declared as
`image/jpeg` → stored, and `http://127.0.0.1:8820/probe.php.jpg` **executes**
it (Apache `AddHandler` runs PHP in any extension position). `.html` / `UP.HTML`
are served as `text/html` (stored XSS).

### BUSL-09 — malicious files
`/products/import` extracts zip entries by raw path join — **zip-slip**:
an entry `../../pwned.php` escapes `/uploads/imports/<id>/` into the web root
and executes at `:8820/pwned.php`. A script-bearing SVG uploaded as an avatar
is served inline as `image/svg+xml` with the `<script>` intact. All effects
stay inside the compose network.

### BUSL-10 — payment functionality
Three flaws, one flow:
1. `POST /payment/create {"order_id":1,"amount":0.01}` — the client overrides
   the amount sent to the PSP; a 500.00 order is settled for 0.01.
2. `POST /payment/callback {"order_id":2,"intent_id":"pi_does_not_exist",
   "status":"succeeded"}` — unauthenticated, unverified, never reconciled.
3. `POST /order/refund {"order_id":1,"amount":-25}` — a negative refund
   **credits** 25.00 to the attacker.

### BUSL-11 — denial of inventory
`/cart/add` reserves stock immediately with `expires_at=NULL`, no per-user
cap, and the expiry sweep (`POST /lab/sweep`) never releases anything.
Register an attacker, `POST /cart/add {"product_id":3,"quantity":3}` (all 3
sneakers, never paid). Legitimate `bob`'s checkout → `409 insufficient stock`,
before and after the sweep. Bounded and reversible: `POST /lab/reset`
restores everything (the probe uses it, so the suite is idempotent).

## Reset / teardown

```bash
curl -X POST http://127.0.0.1:8800/lab/reset   # reseed DB + wipe uploads
docker compose down -v                          # full teardown
```