# µIDS Sentinel Grid

A Python/Flask-based Network Intrusion Detection System (IDS) with a Wireshark-inspired dark-theme web dashboard. Combines real-time packet simulation, Snort-style rule-based detection, and a trained Random Forest ML classifier.

---

## How to Run

**Requirements:** Python 3.9+

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the web dashboard
python3 app.py
```

Open **http://localhost:5000** in your browser. You should see the dashboard with a green "Connected" badge in the bottom right.

### Live packet capture in the dashboard

By default the dashboard runs in **simulation mode** — it shows synthetic packets and never raises real alerts (any "alert" against simulated traffic would be fake by definition).

To capture **real packets** from a network interface and have the dashboard fire **real alerts** when those packets match a loaded rule, run on a host with a real NIC and root privileges:

```bash
# Linux / macOS (use the interface name shown in the dropdown, e.g. eth0, wlan0, en0)
sudo LIVE_CAPTURE=1 python3 app.py
```

In live mode the dashboard captures every Ethernet frame on the chosen interface — TCP, UDP, ICMP, ARP, IPv6, plus higher-level protocols detected by port (HTTP, HTTPS/TLS, DNS, SSH, **FTP**, SMTP, etc.) — parses each packet, shows its layer tree and hex bytes, and only fires an alert when it strictly matches a rule in `default.rules` / `eval.rules`.

> Live capture cannot run in cloud sandboxes (including Replit) because raw L2 sockets need root and a real interface. Use it on a local machine.

### CLI mode (terminal-only, no dashboard)

```bash
sudo python3 main.py <INTERFACE> [RULE_PATH]
# Example: sudo python3 main.py eth0 default.rules
```

---

## Features

- Real-time packet capture simulation with live WebSocket updates
- Rule-based intrusion detection (Snort-style rules)
- ML classifier using a trained Random Forest pipeline (12 attack classes)
- Wireshark-style dark UI with Packets, Alerts, Statistics, Classifier, and Rules tabs
- Filterable packet list with threat level indicators and traffic charts
- CSV upload to swap in your own feature dataset

---

## Using the Dashboard

| Action | How |
|---|---|
| Start packet capture | Click **Start** in the toolbar |
| Pause / Stop capture | Click **Pause** or **Stop** |
| Filter packets | Type in the Filter bar (e.g. `tcp`, `192.168.0.1`, `CRITICAL`) |
| View intrusion alerts | Click the **Alerts** tab |
| View traffic stats | Click the **Statistics** tab |
| Run ML classifier | Click **Classifier** tab → fill features → **Predict** |
| Load your own CSV | Classifier tab → **Load CSV** → pick a `.csv` file |
| View/edit rules | Click the **Rules** tab |
| Export capture | Click **Save** in the toolbar |

---

## ML Classifier

The classifier uses a trained Random Forest pipeline (`random_forest_pipeline.joblib`) to detect 12 traffic classes:

`BENIGN`, `Bot`, `DDoS`, `DoS GoldenEye`, `DoS Hulk`, `DoS Slowhttptest`, `DoS slowloris`, `FTP-Patator`, `Heartbleed`, `Infiltration`, `PortScan`, `SSH-Patator`

Click **Fill Defaults** to populate all 81 feature fields with median values from the sample training data, then click **Predict**.

> The model file (`random_forest_pipeline.joblib`) must be present in the project root. If missing, the dashboard still runs but the Classifier tab will return an error.

To train and export your own model:

```python
import joblib
joblib.dump(pipeline, 'random_forest_pipeline.joblib')
```

---

## Rule Syntax

```
PROTO [!]IP|any:[!]PORT|any ->|<> [!]IP|any:[!]PORT|any *PAYLOAD
```

Examples:

```
ICMP 1.1.1.1:any -> 192.168.178.22:any *
TCP !192.0.0.1:[0-8000] <> 127.0.0.1:!8080 *
```

- `PROTO` — TCP, UDP, or ICMP
- `[!]IP|any` — specific IP, `any` matches all, `!` negates
- `[!]PORT|[RANGE]|any` — port, range like `[80-443]`, or `any`
- `->` one-way, `<>` bidirectional
- `*PAYLOAD` — payload pattern to match

---

## Project Structure

```
├── app.py                          # Flask + Socket.IO server, simulation engine
├── classifier.py                   # ML model loading and prediction
├── rules.py                        # Rule engine
├── signature.py                    # Snort rule parser
├── analyzer.py                     # Packet analyzer (CLI mode)
├── sniffer.py                      # Scapy packet sniffer (CLI mode)
├── main.py                         # CLI entry point
├── requirements.txt
├── default.rules                   # Default IDS rules
├── eval.rules                      # Evaluation rules
├── random_forest_pipeline.joblib   # ML model (add manually — not in repo)
├── cleaned_dataset_sample.csv      # Sample dataset for default feature values
├── templates/
│   └── index.html                  # Dashboard UI
└── static/
    ├── css/style.css
    └── js/app.js
```

---

## Troubleshooting

**Blank page or "Cannot connect"**
- Make sure the server is running: `python3 app.py`
- Check the terminal for errors

**Classifier returns an error**
- Ensure `random_forest_pipeline.joblib` is in the project root
- The model must be a scikit-learn Pipeline saved with `joblib.dump()`

**Port 5000 already in use**
- Change the port at the bottom of `app.py`:
  ```python
  socketio.run(app, host='0.0.0.0', port=5001, ...)
  ```

---

## License

MIT
