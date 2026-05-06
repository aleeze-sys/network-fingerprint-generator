def classify(features):
    total_bytes   = features.get("total_bytes", 0)
    mean_size     = features.get("mean_packet_size", 0)
    total_packets = features.get("total_packets", 0)
    unique_ips    = len(features.get("unique_ips", []))
    dns_queries   = len(features.get("dns_queries", []))
    proto         = features.get("protocol_distribution", {})

    https_pct = proto.get("HTTPS", 0)
    tcp_pct   = proto.get("TCP", 0)
    udp_pct   = proto.get("UDP", 0)

    scores = {
        "Streaming":     0,
        "Social Media":  0,
        "Static Content": 0,
        "API-Heavy":     0,
    }

    # ── Streaming ─────────────────────────────────────────────────────────────
    # High byte volume, large packets, HTTPS/TCP dominant, optional UDP (QUIC)
    if total_bytes > 500_000:
        scores["Streaming"] += 40
    if mean_size > 800:
        scores["Streaming"] += 30
    if https_pct > 70 or tcp_pct > 70:
        scores["Streaming"] += 20
    if udp_pct > 30:
        scores["Streaming"] += 10

    # ── Social Media ──────────────────────────────────────────────────────────
    # Many unique IPs, frequent small packets, lots of DNS, mixed protocols
    if unique_ips > 10:
        scores["Social Media"] += 35
    if total_packets > 200 and mean_size < 500:
        scores["Social Media"] += 30
    if dns_queries > 5:
        scores["Social Media"] += 20
    if https_pct > 30:          # widened: fires even at 100 % HTTPS
        scores["Social Media"] += 15

    # ── Static Content ────────────────────────────────────────────────────────
    # Low packet count, minimal DNS, small total transfer
    if total_packets < 50:
        scores["Static Content"] += 40
    if dns_queries <= 2:
        scores["Static Content"] += 30
    if total_bytes < 100_000:
        scores["Static Content"] += 20
    if mean_size < 300:
        scores["Static Content"] += 10

    # ── API-Heavy ─────────────────────────────────────────────────────────────
    # Very small packets, HTTPS dominant (per requirements), rapid cycles
    if mean_size < 200:
        scores["API-Heavy"] += 40
    if https_pct > 80:          # HTTPS dominant as stated in FR-5
        scores["API-Heavy"] += 30
    if total_packets > 100 and total_bytes < 200_000:
        scores["API-Heavy"] += 20
    if dns_queries <= 3:
        scores["API-Heavy"] += 10

    best_label = max(scores, key=scores.get)
    best_score = scores[best_label]

    if best_score < 20:
        return "Unknown", 0

    total_score = sum(scores.values()) or 1
    confidence  = round((best_score / total_score) * 100)

    return best_label, confidence