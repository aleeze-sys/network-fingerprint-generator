import socket
import threading
from urllib.parse import urlparse

import requests
from scapy.all import ARP, DNS, IP, sniff, wrpcap

urllib3 = None
try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass


def resolve_all_hosts(url):
    hostname = urlparse(url).hostname
    if not hostname:
        return set()
    ips = set()
    try:
        for result in socket.getaddrinfo(hostname, None):
            addr = result[4][0]
            if addr:
                ips.add(addr)
    except Exception:
        pass
    return ips


def capture_packets(url, pcap_path, duration=10):
    target_ips = resolve_all_hosts(url)
    packets = []

    def packet_filter(pkt):
        # Always keep ARP — no IP layer
        if ARP in pkt:
            packets.append(pkt)
            return

        if IP not in pkt:
            return

        # Always keep DNS so we capture UDP port 53 queries
        if DNS in pkt:
            packets.append(pkt)
            return

        # Fallback: no target IPs resolved, capture all IP traffic
        if not target_ips:
            packets.append(pkt)
            return

        if pkt[IP].dst in target_ips or pkt[IP].src in target_ips:
            packets.append(pkt)

    def fetch_url():
        headers = {"User-Agent": "Mozilla/5.0"}
        timeout = max(2, duration - 1)
        # Multiple hits improve chances of capturing CDN/multi-host traffic
        for _ in range(3):
            try:
                requests.get(
                    url,
                    timeout=timeout,
                    headers=headers,
                    verify=False,
                    allow_redirects=True,
                )
            except Exception:
                pass

    fetch_thread = threading.Thread(target=fetch_url)
    fetch_thread.start()

    sniff(prn=packet_filter, timeout=duration, store=False)

    fetch_thread.join()

    if packets:
        wrpcap(pcap_path, packets)
        return True, len(packets)

    return False, 0