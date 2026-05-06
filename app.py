import os
import uuid

import urllib3
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from capture import capture_packets
from extract import extract_features
from fingerprint import generate_fingerprint

app = Flask(__name__, template_folder="templates")
CORS(app)

CAPTURE_DIR = "captures"
os.makedirs(CAPTURE_DIR, exist_ok=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    clean = (url or "").strip()
    if not clean:
        return ""
    if not clean.startswith(("http://", "https://")):
        clean = f"https://{clean}"
    return clean


def _validate_url(url: str) -> bool:
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def _run_analysis(url: str, duration: int):
    """Capture → extract → fingerprint. Returns fingerprint dict or None."""
    pcap_path = os.path.join(CAPTURE_DIR, f"{uuid.uuid4().hex}.pcap")

    success, count = capture_packets(url, pcap_path, duration=duration)
    if not success or count == 0:
        return None

    features = extract_features(pcap_path)
    if not features:
        return None

    fp = generate_fingerprint(url, features)

    # Clean up temp pcap
    try:
        os.remove(pcap_path)
    except Exception:
        pass

    return fp


def _parse_duration(raw, default=10) -> int:
    try:
        return max(3, min(int(raw), 30))
    except (TypeError, ValueError):
        return default


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    payload  = request.get_json(silent=True) or {}
    url      = _normalize_url(payload.get("url", ""))
    duration = _parse_duration(payload.get("duration", 10))

    if not url:
        return jsonify({"ok": False, "error": "Please enter a website URL first."}), 400
    if not _validate_url(url):
        return jsonify({"ok": False, "error": "Could not read that URL. Check the format."}), 400

    fp = _run_analysis(url, duration)
    if not fp:
        return jsonify({
            "ok": False,
            "error": "No traffic captured. Try another URL or increase capture time.",
        }), 400

    return jsonify({"ok": True, "fingerprint": fp})


@app.route("/api/compare", methods=["POST"])
def compare():
    payload  = request.get_json(silent=True) or {}
    url1     = _normalize_url(payload.get("url1", ""))
    url2     = _normalize_url(payload.get("url2", ""))
    duration = _parse_duration(payload.get("duration", 10))

    if not url1 or not url2:
        return jsonify({"ok": False, "error": "Please provide both URLs for comparison."}), 400
    if not _validate_url(url1) or not _validate_url(url2):
        return jsonify({"ok": False, "error": "One or both URLs look invalid. Please check."}), 400

    fp1 = _run_analysis(url1, duration)
    fp2 = _run_analysis(url2, duration)

    if not fp1 or not fp2:
        return jsonify({"ok": False, "error": "Could not capture one of the websites."}), 400

    diff = {
        "more_bytes":         url1 if fp1["total_bytes"]      >= fp2["total_bytes"]      else url2,
        "more_unique_ips":    url1 if len(fp1["unique_ips"])   >= len(fp2["unique_ips"])  else url2,
        "higher_mean_packet": url1 if fp1["mean_packet_size"]  >= fp2["mean_packet_size"] else url2,
        "label1":             fp1["behavior_label"],
        "label2":             fp2["behavior_label"],
        "bytes_diff":         abs(fp1["total_bytes"]      - fp2["total_bytes"]),
        "packets_diff":       abs(fp1["total_packets"]    - fp2["total_packets"]),
        "mean_size_diff":     round(abs(fp1["mean_packet_size"] - fp2["mean_packet_size"]), 2),
        "unique_ips_diff":    abs(len(fp1["unique_ips"])   - len(fp2["unique_ips"])),
    }

    return jsonify({"ok": True, "fingerprint1": fp1, "fingerprint2": fp2, "diff": diff})


# Alias so both /api/capture and /api/analyze work
@app.route("/api/capture", methods=["POST"])
def capture():
    return analyze()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)