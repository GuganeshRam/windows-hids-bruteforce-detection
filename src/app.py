import json
import os

from flask import Flask, jsonify, render_template

import detector

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "logs.json")

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/logs")
def api_logs():

    # Prefer the in-memory state (always current); fall back to the file.
    state = detector.get_state()
    if state.get("status") == "starting" and os.path.exists(LOG_PATH):
        try:
            with open(LOG_PATH) as f:
                state = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return jsonify(state)


@app.route("/api/reset", methods=["POST"])
def api_reset():

    if os.path.exists(LOG_PATH):
        os.remove(LOG_PATH)
    return jsonify({"ok": True})


if __name__ == "__main__":
    detector.start_in_background(LOG_PATH)
    app.run(host="0.0.0.0", port=5000, debug=False)
