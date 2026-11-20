"""M03 OAuth2 Authorization Server - INTENTIONALLY VULNERABLE training target.

Covers WSTG-ATHZ-05 sub-document 05.1 (Authorization Server weaknesses).
Every weakness below is deliberate. Do not deploy.
"""
import json
import secrets
import time

from flask import Flask, jsonify, request

app = Flask(__name__)

CLIENTS = {
    "portal": {"secret": "portal-secret",
               "redirect": "http://127.0.0.1:8300/oauth/callback"},
    "mobile": {"secret": "mobile-secret",
               "redirect": "http://127.0.0.1:8300/oauth/mobile"},
}
USERS = {
    "alice": {"password": "Password123!", "role": "user",
              "private": "ALICE-AS-SECRET: salary 90000"},
    "bob": {"password": "Password123!", "role": "user",
            "private": "BOB-AS-SECRET: salary 85000"},
    "admin": {"password": "AdminPass123!", "role": "admin",
              "private": "ADMIN-AS-SECRET: master key mk-42"},
}
CODES = {}
TOKENS = {}


@app.get("/health")
def health():
    return "ok"


@app.get("/oauth/authorize")
def authorize():
    v = request.args
    cid = v.get("client_id", "")
    redirect = v.get("redirect_uri", "")
    rtype = v.get("response_type", "code")
    scope = v.get("scope", "read")
    state = v.get("state")
    if cid not in CLIENTS:
        return jsonify({"error": "unknown client"}), 400
    # WEAK: substring match instead of exact registered-URI comparison.
    if CLIENTS[cid]["redirect"] not in redirect:
        return jsonify({"error": "invalid redirect_uri"}), 400
    # Lab shortcut: resource-owner credentials passed directly (no login UI).
    u, p = v.get("username", ""), v.get("password", "")
    if u not in USERS or USERS[u]["password"] != p:
        return jsonify({"error": "resource owner authentication required"}), 401
    # WEAK: any requested scope (incl. 'admin') granted without consent.
    if rtype == "token":
        # Deprecated implicit flow: token in the URL fragment.
        tok = secrets.token_hex(16)
        TOKENS[tok] = {"user": u, "scope": scope, "client_id": cid}
        frag = f"access_token={tok}&token_type=bearer&expires_in=3600"
        if state:
            frag += f"&state={state}"
        sep = "#" if "#" not in redirect else "&"
        return "", 302, {"Location": f"{redirect}{sep}{frag}"}
    code = secrets.token_hex(8)
    CODES[code] = {"client_id": cid, "user": u, "scope": scope,
                   "redirect_uri": redirect, "expires": time.time() + 60,
                   "used": False, "code_challenge": v.get("code_challenge"),
                   "code_challenge_method": v.get("code_challenge_method")}
    loc = f"{redirect}{'&' if '?' in redirect else '?'}code={code}"
    if state:
        loc += f"&state={state}"
    return "", 302, {"Location": loc}


@app.route("/oauth/token", methods=["POST", "GET"])
def token():
    # WEAK: client_secret accepted from the URL query string (request.values).
    v = request.values
    cid = v.get("client_id", "")
    csec = v.get("client_secret", "")
    if cid not in CLIENTS or CLIENTS[cid]["secret"] != csec:
        return jsonify({"error": "invalid_client"}), 401
    code = v.get("code", "")
    c = CODES.get(code)
    if not c:
        return jsonify({"error": "invalid_grant"}), 400
    # WEAK: 'used' flag recorded but never enforced -> code replay.
    # WEAK: 'expires' recorded but never checked -> expired codes accepted.
    # WEAK: code not bound to the requesting client_id.
    # WEAK: redirect_uri not compared against the one used at authorize.
    if c.get("code_challenge") and v.get("code_verifier"):
        if v["code_verifier"] != c["code_challenge"]:
            return jsonify({"error": "invalid_grant (pkce)"}), 400
    # WEAK: PKCE downgrade - verifier simply optional even when challenge was sent.
    c["used"] = True
    # WEAK: scope escalation at the token endpoint.
    scope = v.get("scope") or c["scope"]
    tok = secrets.token_hex(16)
    TOKENS[tok] = {"user": c["user"], "scope": scope, "client_id": cid}
    return jsonify({"access_token": tok, "token_type": "bearer",
                    "expires_in": 3600, "scope": scope})


def _token_record():
    t = (request.args.get("access_token")
         or request.headers.get("Authorization", "").removeprefix("Bearer ").strip())
    return TOKENS.get(t)


@app.get("/oauth/userinfo")
def userinfo():
    rec = _token_record()
    if not rec:
        return jsonify({"error": "invalid_token"}), 401
    return jsonify({"sub": rec["user"], "role": USERS[rec["user"]]["role"],
                    "scope": rec["scope"]})


@app.get("/api/resource")
def resource():
    rec = _token_record()
    if not rec:
        return jsonify({"error": "invalid_token"}), 401
    if rec["scope"] == "admin":
        return jsonify({"users": {k: v["private"] for k, v in USERS.items()}})
    return jsonify({"user": rec["user"], "private": USERS[rec["user"]]["private"]})


@app.post("/debug/expire-code")
def expire_code():
    """Lab knob: backdate a code's expiry so elapsed time can be simulated."""
    code = request.values.get("code", "")
    if code not in CODES:
        return jsonify({"error": "unknown code"}), 404
    CODES[code]["expires"] = time.time() - 3600
    return jsonify({"ok": True, "code": code, "expired": True})


@app.get("/debug/code/<code>")
def code_info(code):
    c = CODES.get(code)
    if not c:
        return jsonify({"error": "unknown code"}), 404
    return jsonify(c)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)