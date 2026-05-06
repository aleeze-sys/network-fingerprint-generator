from datetime import datetime

from classify import classify


def generate_fingerprint(url, features):
    if not features:
        return None

    label, confidence = classify(features)

    proto = features.get("protocol_distribution", {})
    top_protocol = max(proto, key=proto.get) if proto else "Unknown"

    fingerprint = {
        # ── Identity ──────────────────────────────────────────────────────────
        "site_url":           url,
        "capture_timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds":   features["duration"],

        # ── Volume ────────────────────────────────────────────────────────────
        "total_packets":      features["total_packets"],
        "total_bytes":        features["total_bytes"],

        # ── Packet size stats ─────────────────────────────────────────────────
        "mean_packet_size":   features["mean_packet_size"],
        "min_packet_size":    features["min_packet_size"],
        "max_packet_size":    features["max_packet_size"],

        # ── Protocol ──────────────────────────────────────────────────────────
        "top_protocol":        top_protocol,
        "protocol_distribution": features["protocol_distribution"],

        # ── Hosts & DNS ───────────────────────────────────────────────────────
        "unique_ips":         features["unique_ips"],
        "dns_queries":        features["dns_queries"],

        # ── Charts data ───────────────────────────────────────────────────────
        "size_buckets":       features["size_buckets"],
        "timeline":           features["timeline"],   # bytes per second list

        # ── Classification ────────────────────────────────────────────────────
        "behavior_label":     label,
        "confidence":         confidence,
    }

    return fingerprint