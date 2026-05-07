# 🔍 Network Fingerprint Generator & Website Behavior Profiler

A web-based tool that captures **live network traffic** when you visit a website, analyzes the packets, and generates a unique **network fingerprint** — a behavioral profile showing how a site communicates.

Built as an educational tool for networking students to visually compare real-world traffic patterns between different websites.

---

## 📸 Features

- 🟦 **Live packet capture** using Scapy on your active network interface
- 📊 **Protocol distribution** pie chart (HTTPS, TCP, UDP, DNS, ICMP, ARP)
- 📦 **Packet size histogram** grouped into 4 size buckets
- 📈 **Traffic timeline** — bytes per second over the capture window
- 🤖 **Automatic behavior classification** — Streaming, Social Media, Static Content, API-Heavy
- 🆚 **Side-by-side website comparison** with winner summary and difference metrics
- 🌐 **Unique destination IP list** for every capture session

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3, Flask, Flask-CORS |
| Packet Capture | Scapy |
| HTTP Requests | Python requests |
| Frontend | HTML, CSS, JavaScript |
| Charts | Chart.js |
| Data Format | pcap (capture), JSON (fingerprint) |

---

## 📁 Project Structure

```
network-fingerprint/
├── app.py            # Flask server & REST API routes
├── capture.py        # Scapy packet capture module
├── extract.py        # Feature extraction from pcap files
├── fingerprint.py    # Fingerprint assembly & JSON output
├── classify.py       # Rule-based behavior classifier
├── templates/
│   └── index.html    # Frontend single-page interface
└── captures/         # Temporary pcap files (auto-created)
```

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/network-fingerprint.git
cd network-fingerprint
```

### 2. Create a virtual environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / Mac
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install flask flask-cors scapy requests
```

### 4. Run the app

> ⚠️ **Scapy requires elevated privileges** to capture raw packets.

```bash
# Windows — run terminal as Administrator, then:
python app.py

# Linux / Mac
sudo python app.py
```

### 5. Open in browser

```
http://localhost:5000
```

---

## 🚀 Usage

### Single URL Analysis
1. Enter a URL in the input field (e.g. `https://youtube.com`)
2. Set capture duration (default: 10 seconds)
3. Click **Analyze**
4. View the fingerprint summary, charts, and unique IP list

### Compare Two Websites
1. Switch to **Compare** mode
2. Enter two URLs
3. Click **Compare**
4. See side-by-side fingerprints, overlapping timeline chart, and winner summary

---

## 📊 Behavior Labels

| Label | Traffic Pattern |
|-------|----------------|
| 🎬 Streaming | High byte volume, large packets, TCP/HTTPS dominant |
| 📱 Social Media | Many unique IPs, frequent small packets, lots of DNS |
| 📄 Static Content | Low packet count, minimal DNS, small total transfer |
| ⚡ API-Heavy | Very small packets, HTTPS dominant, rapid cycles |
| ❓ Unknown | Does not match any pattern |

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/analyze` | Analyze a single URL |
| POST | `/api/compare` | Compare two URLs side by side |
| GET | `/` | Serve the frontend |

### Example request

```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "duration": 10}'
```

---

## ⚠️ Known Limitations

- Traffic is generated using Python `requests`, which only fetches raw HTML — not images, CSS, or JS assets. This means the traffic timeline will show a spike in the first few seconds then drop to zero, which is expected behavior.
- Capture accuracy depends on your network interface and OS permissions.
- On Windows, Npcap must be installed for Scapy to work. Download from [npcap.com](https://npcap.com).

---

## 📋 Requirements

- Python 3.8+
- Windows: [Npcap](https://npcap.com) installed
- Linux/Mac: `libpcap` (usually pre-installed)
- Administrator / sudo privileges for packet capture

---

## 📄 License

This project was built for educational purposes as part of a Computer Networks course.

---

