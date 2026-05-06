from scapy.all import rdpcap
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import ARP
import statistics

def extract_features(pcap_path):
    try:
        packets = rdpcap(pcap_path)
    except Exception:
        return None

    if not packets:
        return None

    total_packets = len(packets)
    sizes = [len(pkt) for pkt in packets]
    total_bytes = sum(sizes)
    timestamps = [float(pkt.time) for pkt in packets]

    protocol_counts = {"HTTPS": 0, "TCP": 0, "UDP": 0, "DNS": 0, "ICMP": 0, "ARP": 0, "HTTP": 0, "OTHER": 0}
    unique_ips = set()
    dns_queries = []
    size_buckets = {"0-100": 0, "101-500": 0, "501-1000": 0, "1001-1500": 0}

    for pkt in packets:
        size = len(pkt)
        if size <= 100:       size_buckets["0-100"] += 1
        elif size <= 500:     size_buckets["101-500"] += 1
        elif size <= 1000:    size_buckets["501-1000"] += 1
        else:                 size_buckets["1001-1500"] += 1

        if ARP in pkt:
            protocol_counts["ARP"] += 1

        elif IP in pkt:
            unique_ips.add(pkt[IP].dst)
            unique_ips.add(pkt[IP].src)

            if DNS in pkt and pkt[DNS].qr == 0:
                protocol_counts["DNS"] += 1
                if DNSQR in pkt:
                    try:
                        dns_queries.append(pkt[DNSQR].qname.decode("utf-8").rstrip("."))
                    except Exception:
                        pass
            elif TCP in pkt:
                if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                    protocol_counts["HTTPS"] += 1
                elif pkt[TCP].dport in (80, 8080) or pkt[TCP].sport in (80, 8080):
                    protocol_counts["HTTP"] += 1
                else:
                    protocol_counts["TCP"] += 1
            elif UDP in pkt:
                protocol_counts["UDP"] += 1
            elif ICMP in pkt:
                protocol_counts["ICMP"] += 1
            else:
                protocol_counts["OTHER"] += 1
        else:
            protocol_counts["OTHER"] += 1

    total_proto = sum(protocol_counts.values()) or 1
    protocol_distribution = {
        k: round((v / total_proto) * 100, 1)
        for k, v in protocol_counts.items() if v > 0
    }

    inter_arrival_times = [
        round(timestamps[i] - timestamps[i - 1], 4)
        for i in range(1, len(timestamps))
    ]

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "packet_sizes": sizes,
        "mean_packet_size": round(statistics.mean(sizes), 1) if sizes else 0,
        "min_packet_size": min(sizes) if sizes else 0,
        "max_packet_size": max(sizes) if sizes else 0,
        "protocol_distribution": protocol_distribution,
        "protocol_counts": protocol_counts,
        "unique_ips": list(unique_ips),
        "dns_queries": list(set(dns_queries)),
        "inter_arrival_times": inter_arrival_times,
        "size_buckets": size_buckets,
        "timeline": build_timeline(packets),
        "duration": round(timestamps[-1] - timestamps[0], 2) if len(timestamps) > 1 else 0,
    }

def build_timeline(packets):
    if not packets:
        return []
    start = float(packets[0].time)
    buckets = {}
    for pkt in packets:
        second = int(float(pkt.time) - start)
        buckets[second] = buckets.get(second, 0) + len(pkt)
    max_sec = max(buckets.keys())
    return [buckets.get(i, 0) for i in range(max_sec + 1)]