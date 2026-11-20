"""Export worker - the SECOND component of the incubated vulnerability (INJT-14).

The filename stored benignly by the portal is later concatenated into a shell
command here, so a payload that was harmless at store time detonates at recall.
"""
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify(ok=True)


@app.post("/export")
def export():
    filename = request.form.get("filename", "report.txt")
    content = request.form.get("content", "")
    # VULNERABLE: stored filename concatenated into a shell command.
    cmd = f"mkdir -p /export && printf '%s' '{content}' > /export/{filename}"
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return jsonify(command=cmd, stdout=proc.stdout, stderr=proc.stderr,
                       returncode=proc.returncode)
    except subprocess.TimeoutExpired:
        return jsonify(command=cmd, error="timeout"), 504


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)