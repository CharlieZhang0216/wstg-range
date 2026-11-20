"""Mock payment provider for the WSTG-BUSL lab (in-range only, no real PSP).

Simulates a card processor with payment intents. It is deliberately minimal:
it records intents and marks them paid when the test card is charged. The shop
is supposed to reconcile amounts and verify callbacks - it does not.
"""
import uuid

from flask import Flask, jsonify, request

app = Flask(__name__)
INTENTS = {}


@app.get("/health")
def health():
    return jsonify(ok=True, provider="acme-pay-mock")


@app.post("/intents")
def create_intent():
    d = request.get_json(force=True)
    iid = "pi_" + uuid.uuid4().hex[:16]
    INTENTS[iid] = {
        "intent_id": iid,
        "amount": d.get("amount"),
        "currency": d.get("currency", "USD"),
        "order_ref": d.get("order_ref"),
        "status": "requires_payment",
    }
    return jsonify(INTENTS[iid]), 201


@app.get("/intents/<iid>")
def get_intent(iid):
    if iid not in INTENTS:
        return jsonify(error="no such intent"), 404
    return jsonify(INTENTS[iid])


@app.post("/intents/<iid>/pay")
def pay_intent(iid):
    """Charge the synthetic test card. No real money, no external calls."""
    if iid not in INTENTS:
        return jsonify(error="no such intent"), 404
    INTENTS[iid]["status"] = "succeeded"
    INTENTS[iid]["method"] = "test_card_4242"
    return jsonify(INTENTS[iid])


@app.get("/intents")
def list_intents():
    return jsonify(intents=list(INTENTS.values()))


@app.post("/reset")
def reset():
    """Lab helper: clear all intents so probe runs are idempotent."""
    INTENTS.clear()
    return jsonify(ok=True, reset=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)