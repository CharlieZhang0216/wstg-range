"""In-range attacker listener + simulated spreadsheet client.

Roles:
  * attacker-controlled host (evil.attacker.test / portal.trusted.lab aliases)
    that logs every callback - used by SSRF, redirect validation, incubated
    recall and CSV HYPERLINK exfiltration.
  * /csv-open simulates a spreadsheet application opening an exported CSV:
    formula cells are interpreted, HYPERLINK targets are fetched (exfil) and
    DDE commands are recorded. No real Excel is available headless, so this
    faithfully reproduces the client-side interpretation step in-range.
"""
import csv
import io
import re
import urllib.request

from flask import Flask, request, jsonify

app = Flask(__name__)
HITS = []


@app.before_request
def log():
    if request.path in ("/hits", "/health", "/reset", "/csv-open"):
        return
    HITS.append({"method": request.method, "host": request.headers.get("Host", ""),
                 "path": request.full_path, "ua": request.headers.get("User-Agent", "")})


@app.get("/health")
def health():
    return jsonify(ok=True)


@app.get("/hits")
def hits():
    return jsonify(hits=HITS)


@app.post("/reset")
def reset():
    HITS.clear()
    return jsonify(ok=True)


@app.route("/", defaults={"p": ""})
@app.route("/<path:p>")
def catch(p):
    return jsonify(listener="evil.attacker.test", received=request.full_path)


def _hyperlink_url(cell):
    m = re.search(r'HYPERLINK\(\s*"([^"]+)"', cell, re.I)
    return m.group(1) if m else None


@app.post("/csv-open")
def csv_open():
    text = request.get_data(as_text=True)
    rows = list(csv.reader(io.StringIO(text)))
    formulas, fetched, dde = [], [], []
    for row in rows:
        for cell in row:
            c = cell.strip()
            if c[:1] in ("=", "+", "-", "@"):
                formulas.append(c)
                url = _hyperlink_url(c)
                if url:
                    try:
                        with urllib.request.urlopen(url, timeout=6) as r:
                            fetched.append({"url": url, "status": r.status})
                    except Exception as e:
                        fetched.append({"url": url, "error": str(e)})
                if re.match(r"=(cmd|MSEXCEL|DDE)", c, re.I) or "|" in c:
                    dde.append(c)
    return jsonify(formula_cells=formulas, hyperlinks_fetched=fetched, dde_attempts=dde)


if __name__ == "__main__":
    import threading
    from werkzeug.serving import make_server
    # Serve on both 80 (so in-range hosts like evil.attacker.test resolve here
    # for server-side redirect validation / SSRF) and 8080 (published UI/API).
    s80 = make_server("0.0.0.0", 80, app, threaded=True)
    s8080 = make_server("0.0.0.0", 8080, app, threaded=True)
    threading.Thread(target=s80.serve_forever, daemon=True).start()
    s8080.serve_forever()