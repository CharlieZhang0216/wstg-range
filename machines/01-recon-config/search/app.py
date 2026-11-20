"""In-range search index (WSTG-INFO-01).

A real engagement uses a public search engine. This lab must not touch the
internet, so a crawler indexes the target and exposes the same dorking surface:
`site:`, `inurl:`, `intitle:` and free text over titles, bodies and URLs.
"""
import os
import re
import threading
import urllib.parse
import urllib.request
from html.parser import HTMLParser

from flask import Flask, jsonify, request

app = Flask(__name__)
TARGET = os.environ.get("CRAWL_TARGET", "http://front/")
_lock = threading.Lock()
INDEX = {}


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.title = ""
        self._in_title = False
        self.text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v:
                    self.links.append(v)
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        self.text.append(data)


def _fetch(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.read().decode("utf-8", "replace")
    except Exception:
        return ""


def crawl():
    base = TARGET.rstrip("/")
    origin = urllib.parse.urlsplit(base).netloc
    seen, queue = set(), [base + "/", base + "/robots.txt", base + "/sitemap.xml"]
    while queue and len(seen) < 200:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        body = _fetch(url)
        if not body:
            continue
        p = Links()
        try:
            p.feed(body)
        except Exception:
            pass
        with _lock:
            INDEX[url] = {"title": p.title.strip(), "body": " ".join(p.text)[:4000], "url": url}
        for href in p.links + re.findall(r"<loc>([^<]+)</loc>", body) + re.findall(r"Disallow:\s*(\S+)", body):
            nxt = urllib.parse.urljoin(url, href.strip())
            if urllib.parse.urlsplit(nxt).netloc == origin and nxt not in seen:
                queue.append(nxt)
    with _lock:
        INDEX["_meta"] = {"crawled": len(seen), "target": base}


@app.route("/health")
def health():
    return "ok"


@app.route("/recrawl", methods=["POST", "GET"])
def recrawl():
    crawl()
    with _lock:
        return jsonify({"indexed": len(INDEX) - 1})


@app.route("/index.json")
def index_json():
    with _lock:
        return jsonify({k: v for k, v in INDEX.items() if k != "_meta"})


@app.route("/search")
def search():
    q = request.args.get("q", "")
    site = request.args.get("site", "")
    tokens = q.split()
    free = [t.lower() for t in tokens if not t.startswith(("site:", "inurl:", "intitle:"))]
    inurl = [t[6:].lower() for t in tokens if t.startswith("inurl:")]
    intitle = [t[8:].lower() for t in tokens if t.startswith("intitle:")]
    for t in tokens:
        if t.startswith("site:"):
            site = t[5:]

    with _lock:
        docs = [(k, v) for k, v in INDEX.items() if k != "_meta"]

    hits = []
    for url, doc in docs:
        title = doc["title"].lower()
        blob = (url + " " + title + " " + doc["body"]).lower()
        if site and site.lower() not in url.lower():
            continue
        if not all(t in blob for t in free):
            continue
        if not all(t in url.lower() for t in inurl):
            continue
        if not all(t in title for t in intitle):
            continue
        hits.append({"url": url, "title": doc["title"], "snippet": doc["body"][:200]})
    return jsonify({"query": q, "count": len(hits), "results": hits[:50]})


@app.route("/")
def root():
    return (
        "<html><body><h1>Range search index</h1>"
        "<form action='/search'><input name='q' size='60' placeholder='site:portal.lab.test password'>"
        "<button>Search</button></form>"
        "<p><a href='/index.json'>index.json</a> | <a href='/recrawl'>recrawl</a></p>"
        "</body></html>"
    )


threading.Thread(target=crawl, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)