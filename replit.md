# µIDS — Micro Intrusion Detection System Dashboard

A Python-based network IDS with a modern Wireshark-inspired web dashboard.

## Architecture

### Backend (Python / Flask)
- `app.py` — Flask + Socket.IO web server (port 5000); background packet simulation thread; integrates with the real IDS rules engine and ML classifier
- `rules.py` — Rule parser and validator
- `signature.py` — Packet signature representation and matching logic
- `classifier.py` — ML-based traffic classifier (Random Forest) with prediction API
- `analyzer.py` — Multiprocessing packet analyzer (used by CLI mode)
- `sniffer.py` — Scapy-based packet sniffer (used by CLI mode)
- `main.py` — Original CLI entry point (requires root + network interface)

### ML Model
- `random_forest_pipeline.joblib` — Trained Random Forest pipeline for traffic classification
- `cleaned_dataset_sample.csv` — Feature info sample (2000 rows from training data)

### Frontend
- `templates/index.html` — Full dashboard HTML
- `static/css/style.css` — Dark theme CSS
- `static/js/app.js` — Dashboard JavaScript (Socket.IO, Chart.js)

### Rules
- `default.rules` — Default IDS rules (4 rules)
- `eval.rules` — Evaluation rules for multiple clients

## Dashboard Features
- **Top menu bar** — File, Edit, View, Capture, Analyze, Statistics menus
- **Toolbar** — Start/Stop/Pause/Restart capture, Open/Save, Rules, Stats, Classify
- **Filter bar** — Real-time filter with green/red validation feedback
- **Packet table** — Sortable columns, color-coded by threat level and protocol
- **Packet Details** — Expandable layer tree (Frame, Ethernet, IP, TCP/UDP, App)
- **Hex viewer** — Offset + hex + ASCII representation of raw packet bytes
- **Alerts tab** — Full alert history with attack type classification
- **Statistics tab** — Protocol pie chart, traffic rate line chart, threat bar chart, counters
- **Classifier tab** — ML traffic classifier with 81 input features, prediction with probability bars
- **Rules tab** — View all loaded rules with inline validator
- **Sidebar** — Threat level indicator, live alerts feed, mini charts, active rules list
- **Status bar** — Interface, packet count, filter count, alerts, uptime
- **Toast notifications** — Real-time alert toasts for intrusion detections

## Running
- **Web Dashboard** (default): `python3 app.py` → http://localhost:5000
- **CLI mode** (requires root + interface): `sudo python3 main.py <INTERFACE> [RULE_PATH]`

## Dependencies
- `flask` + `flask-socketio` + `eventlet` — Web server and real-time updates
- `scapy>=2.4.1` — Packet structures and parsing (do NOT install scapy-python3, it conflicts)
- `netifaces>=0.10.9` — Network interface info
- `scikit-learn` + `joblib` + `pandas` + `numpy` — ML classifier

## Replit Migration Notes
- `scapy-python3` must NOT be installed — it overrides `scapy` and breaks imports
- `rules.py` uses `Signature(line)` constructor (not `Signature.from_snort_rule`)
- `requirements.txt` cleaned of duplicates and the conflicting `scapy-python3` entry

## Workflow
- **Start application** (webview, port 5000): `python3 app.py`
