"""Stand-in SaaS hosting provider used to demonstrate WSTG-CONF-10.

A customer deprovisioned their site but left the DNS CNAME in place. The
provider answers with the characteristic "unclaimed host" 404, and anyone may
claim that hostname - which is exactly what a subdomain takeover is.
"""
import threading

from flask import Flask, Response, jsonify, request

app = Flask(__name__)
_lock = threading.Lock()
_claims = {}

UNCLAIMED_BODY = """<!DOCTYPE html>
<html><head><title>Site not found</title></head>
<body>
<h1>There isn't a GitHub Pages site here.</h1>
<p>If you're the owner of this site, claim it to publish your content.</p>
<!-- provider: pages-saas/2.4, host not registered -->
</body></html>
"""


@app.route("/health")
def health():
    return "ok"


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def site(path):
    host = (request.host or "").split(":")[0].lower()
    with _lock:
        claimed = _claims.get(host)
    if claimed is None:
        return Response(UNCLAIMED_BODY, status=404, mimetype="text/html")
    return Response(claimed, status=200, mimetype="text/html")


@app.route("/claim", methods=["POST"])
def claim():
    data = request.get_json(silent=True) or request.form.to_dict()
    host = (data.get("hostname") or "").split(":")[0].lower()
    content = data.get("content") or "<h1>claimed</h1>"
    if not host:
        return jsonify({"error": "hostname required"}), 400
    with _lock:
        _claims[host] = content
    return jsonify({"claimed": host, "status": "ok"}), 201


@app.route("/release", methods=["POST"])
def release():
    """Deprovision a site, leaving any DNS record pointing at it dangling."""
    data = request.get_json(silent=True) or request.form.to_dict()
    host = (data.get("hostname") or "").split(":")[0].lower()
    with _lock:
        existed = _claims.pop(host, None) is not None
    return jsonify({"released": host, "was_claimed": existed})


@app.route("/claims")
def claims():
    with _lock:
        return jsonify({"claimed_hosts": sorted(_claims)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)