"""Server-side document rendering injection (INJT-27).

Renders user-controlled HTML to PDF with headless Chromium. The renderer runs
with web security disabled and file access allowed, so injected HTML/JS can
read local files (file:///etc/passwd), reach internal-only services (SSRF) and
execute JavaScript inside the rendering context.
"""
import base64
import os
import threading
import uuid

from flask import Flask, request, jsonify
from playwright.sync_api import sync_playwright

app = Flask(__name__)
LOCK = threading.Lock()
ARGS = ["--no-sandbox", "--disable-gpu", "--disable-web-security",
        "--allow-file-access-from-files", "--disable-dev-shm-usage"]


@app.get("/health")
def health():
    return jsonify(ok=True)


@app.post("/render")
def render():
    data = request.get_json(force=True, silent=True)
    html = data.get("html", "") if isinstance(data, dict) else request.get_data(as_text=True)
    path = f"/tmp/render-{uuid.uuid4().hex}.html"
    with open(path, "w") as fh:
        fh.write(html)
    reqs, console = [], []
    try:
        with LOCK:
            with sync_playwright() as p:
                browser = p.chromium.launch(args=ARGS)
                page = browser.new_page()
                page.on("request", lambda r: reqs.append(r.url))
                page.on("console", lambda m: console.append(m.text))
                page.goto("file://" + path, wait_until="load", timeout=20000)
                page.wait_for_timeout(2500)
                content = page.content()
                try:
                    pdf = base64.b64encode(page.pdf()).decode()
                except Exception:
                    pdf = None
                browser.close()
        os.unlink(path)
        return jsonify(content=content, requests=reqs, console=console, pdf_base64=pdf)
    except Exception as e:
        return jsonify(error=f"{type(e).__name__}: {e}", requests=reqs, console=console), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)