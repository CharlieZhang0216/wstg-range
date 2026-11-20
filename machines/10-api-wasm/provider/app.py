"""In-range mock payment provider (stands in for Stripe/PayPal - no outbound).

Signs webhook events with HMAC-SHA256 exactly like a real provider would.
The lab's receiver ignores the signature; this service lets a tester capture
a genuine signed event and then forge / tamper / replay it.
"""
import hashlib
import hmac
import json
import os
import time
import urllib.request
import uuid

from flask import Flask, jsonify, request

app = Flask(__name__)
SECRET = os.environ.get("WEBHOOK_PROVIDER_SECRET", "whsec_lab_dev")
TARGET = os.environ.get("WEBHOOK_TARGET", "http://api:5000/webhooks/provider")


def _event(account_id, amount):
    return {
        "event_id": f"evt_{uuid.uuid4().hex}",
        "type": "payment.succeeded",
        "account_id": account_id,
        "amount": amount,
        "currency": "USD",
        "created": int(time.time()),
    }


def _sign(body):
    return hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "mock-provider"})


@app.get("/sample-event")
def sample_event():
    """A genuine, correctly signed event the tester can capture and abuse."""
    ev = _event(int(request.args.get("account_id", 1)), int(request.args.get("amount", 10)))
    body = json.dumps(ev)
    return jsonify({"body": body, "signature": _sign(body.encode()),
                    "header": "X-Provider-Signature", "target": TARGET})


@app.post("/send")
def send():
    """Deliver a genuine signed event to the receiver, like the provider would."""
    d = request.get_json(force=True) if request.data else {}
    ev = _event(int(d.get("account_id", 1)), int(d.get("amount", 10)))
    body = json.dumps(ev).encode()
    req = urllib.request.Request(
        TARGET, data=body,
        headers={"Content-Type": "application/json", "X-Provider-Signature": _sign(body)},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        out = json.loads(resp.read())
    return jsonify({"delivered": ev, "receiver_response": out})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)