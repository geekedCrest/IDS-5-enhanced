# -*- coding: utf-8 -*-
"""
Web ML Classifier backend for the IDS dashboard.

Faithfully reproduces the prediction pipelines of the two desktop apps
(cicids_app_complete.py and cicids_desktop_app.py) so they can be driven from a
browser tab instead of a Tkinter window. The model logic, feature handling and
Gemini reporting are kept identical to the originals — only the GUI layer is web.

Two models are supported:
  * "cyber"  — cicids_app_complete.py: separate model + StandardScaler + encoder;
               inputs are SCALED before prediction. feature names live on
               model.feature_columns.
  * "cicids" — cicids_desktop_app.py: a single bundle dict
               {model, label_encoder, feature_means, feature_columns}; NO scaler
               (raw features), defaults come from feature_means.
"""

import os
import re
import gc
import time
import warnings
from io import BytesIO
from datetime import datetime

import joblib
import numpy as np
import pandas as pd

# The pickled models were trained on an older scikit-learn; silence the
# version-mismatch and feature-name warnings (predictions are unaffected).
warnings.filterwarnings('ignore')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploaded')

# Gemini key resolution: GEMINI_API_KEY env var → gemini_api_key.txt (gitignored).
# The key is NEVER hardcoded here so it is not committed to source control.
def get_gemini_api_key():
    key = os.environ.get('GEMINI_API_KEY', '').strip()
    if key:
        return key
    key_file = os.path.join(BASE_DIR, 'gemini_api_key.txt')
    if os.path.exists(key_file):
        with open(key_file, 'r', encoding='utf-8') as fh:
            fk = fh.read().strip()
            if fk:
                return fk
    return ''

GEMINI_SYSTEM_PROMPT = (
    "You are an expert Senior Cyber Security Analyst & Digital Forensics Examiner. "
    "You will receive network traffic statistics classified by a Random Forest model. "
    "Your job is to draft a formal, highly professional, and comprehensive Executive & "
    "Technical Cyber Security Report fully in English. The report must strictly include the "
    "following clearly structured sections: 1. Executive Summary (overview of network health, "
    "total rows, and attack vs. benign ratio), 2. Detailed Attack Analysis (for each detected "
    "attack type, provide a scientific explanation of how it works, and map the top 5 network "
    "features to it, explaining scientifically why these metrics spiked, such as IAT or "
    "flow_duration), 3. Risk Assessment (severity and impact on infrastructure like Web, FTP, "
    "or SSH servers), 4. Mitigation & Remediation Strategies (clear, actionable engineering "
    "solutions for each attack, e.g., Rate Limiting, Timeout adjustments, Fail2ban, and CDNs). "
    "Maintain a formal, academic, and rigorous tone, avoiding generic descriptions."
)

# ── Per-model registry ────────────────────────────────────────────────────────
CYBER_KEY_FEATURES = [
    ('init_fwd_win_byts', 'Init Fwd Win Bytes', 'Number of bytes sent in the initial window in the forward direction. High values can suggest TCP handshake anomalies or scanning behavior.'),
    ('dst_port', 'Destination Port', 'The destination port of the traffic. Scanning actions often target multiple ports, while specific services like HTTP (80/443) or SSH (22) have known ports.'),
    ('init_bwd_win_byts', 'Init Bwd Win Bytes', 'Number of bytes sent in the initial window in the backward direction. Highly indicative of server responses during connection establishment.'),
    ('fwd_seg_size_min', 'Min Fwd Segment Size', 'Minimum segment size observed in the forward direction. Often reflects TCP header options set by attackers.'),
    ('flow_iat_mean', 'Flow IAT Mean', 'Mean time between two flows. Short intervals are common in automated scripts or high-rate Denial-of-Service attacks.'),
    ('flow_iat_max', 'Flow IAT Max', 'Maximum time between two flows. Useful for identifying periodic beaconing or slow-rate exfiltration.'),
    ('flow_duration', 'Flow Duration', 'Total duration of the network flow in microseconds. Extremely short or excessively long flows can indicate anomalous sessions.'),
    ('fwd_header_len', 'Fwd Header Length', 'Total bytes used for headers in the forward direction. Discrepancies between header size and payload can point to packet craft attacks.'),
    ('flow_pkts_s', 'Flow Packets/s', 'Total number of flow packets per second. Massive spikes indicate flood attacks (e.g., Syn Flood, DDoS).'),
    ('fwd_pkt_len_max', 'Max Fwd Packet Length', 'Maximum size of a packet in the forward direction. Large unexpected packets can be a sign of buffer overflow attempts or exfiltration.'),
    ('protocol', 'Protocol', 'The network protocol used (e.g., TCP=6, UDP=17). Certain attacks are protocol-specific.'),
    ('tot_fwd_pkts', 'Total Forward Packets', 'Total packets sent in the forward direction. High count indicates high-intensity connection attempts.'),
    ('tot_bwd_pkts', 'Total Backward Packets', 'Total packets received in the backward direction. Helps check session symmetry and response ratios.'),
    ('flow_byts_s', 'Flow Bytes/s', 'Total bytes transferred per second. Indicates bandwidth consumption, useful to distinguish volume attacks.'),
]

CICIDS_KEY_FEATURES = [
    ('dst_port', 'Destination Port', 'Destination port: indicates the targeted service or host port, useful to detect scanning and targeted attacks.'),
    ('flow_duration', 'Flow Duration', 'Flow duration: session length which can indicate long-running suspicious connections.'),
    ('tot_fwd_pkts', 'Total Fwd Packets', 'Total forward packets: measures request intensity from the source towards the destination.'),
    ('tot_bwd_pkts', 'Total Backward Packets', 'Total backward packets: measures responses from the destination to the source.'),
    ('fwd_pkt_len_max', 'Fwd Packet Length Max', 'Forward packet max length: large unusual packets can be a sign of certain attacks.'),
    ('flow_byts_s', 'Flow Bytes/s', 'Flow bytes/s: bytes per second indicating the volume and intensity of traffic.'),
]

MODELS = {
    'cyber': {
        'label': 'Cyber RF (scaled)',
        'kind': 'scaled',
        'model_file': os.path.join(UPLOAD_DIR, 'cyber_rf_model.joblib'),
        'scaler_file': os.path.join(UPLOAD_DIR, 'cyber_scaler.joblib'),
        'encoder_file': os.path.join(UPLOAD_DIR, 'cyber_encoder.joblib'),
        'key_features': CYBER_KEY_FEATURES,
        'source': 'cicids_app_complete.py',
    },
    'cicids': {
        'label': 'CICIDS RF (bundle)',
        'kind': 'bundle',
        'model_file': os.path.join(UPLOAD_DIR, 'cicids_rf_model.joblib'),
        'key_features': CICIDS_KEY_FEATURES,
        'source': 'cicids_desktop_app.py',
    },
}


def available_models():
    """List models that are present on disk (for the dashboard selector)."""
    out = []
    for mid, cfg in MODELS.items():
        ready = os.path.exists(cfg['model_file'])
        out.append({'id': mid, 'label': cfg['label'], 'kind': cfg['kind'], 'ready': ready})
    return out


# ── Single-slot lazy cache (bounds RAM to one ~2.6 GB model at a time) ─────────
_loaded = {'id': None, 'obj': None}


def _load(model_id):
    cfg = MODELS[model_id]
    if not os.path.exists(cfg['model_file']):
        raise FileNotFoundError(f"Model file missing: {cfg['model_file']}")

    if cfg['kind'] == 'scaled':
        model = joblib.load(cfg['model_file'])
        scaler = joblib.load(cfg['scaler_file'])
        encoder = joblib.load(cfg['encoder_file'])
        feature_columns = list(model.feature_columns)
        # baseline defaults = scaler training means, aligned to feature_columns
        means = {f: float(scaler.mean_[i]) for i, f in enumerate(feature_columns)}
        return {'kind': 'scaled', 'model': model, 'scaler': scaler, 'encoder': encoder,
                'feature_columns': feature_columns, 'means': means,
                'key_features': cfg['key_features']}

    # bundle (no scaler, raw features)
    b = joblib.load(cfg['model_file'])
    model = b['model']
    encoder = b['label_encoder']
    feature_columns = list(b['feature_columns'])
    feature_means = pd.Series(b['feature_means'])
    means = {f: float(feature_means.get(f, 0.0)) for f in feature_columns}
    return {'kind': 'bundle', 'model': model, 'scaler': None, 'encoder': encoder,
            'feature_columns': feature_columns, 'means': means,
            'feature_means': feature_means, 'key_features': cfg['key_features']}


def _get(model_id):
    if model_id not in MODELS:
        raise ValueError(f'Unknown model: {model_id}')
    if _loaded['id'] != model_id:
        # Evict the previously loaded model first to keep memory bounded.
        _loaded['obj'] = None
        _loaded['id'] = None
        gc.collect()
        _loaded['obj'] = _load(model_id)
        _loaded['id'] = model_id
    return _loaded['obj']


def get_model_info(model_id):
    """Load (if needed) and return feature form + class list for the dashboard."""
    m = _get(model_id)
    feats = []
    for name, label, desc in m['key_features']:
        feats.append({'name': name, 'label': label, 'desc': desc,
                      'default': round(m['means'].get(name, 0.0), 4)})
    return {
        'id': model_id,
        'label': MODELS[model_id]['label'],
        'kind': m['kind'],
        'features': feats,
        'n_features': len(m['feature_columns']),
        'classes': list(map(str, m['encoder'].classes_)),
        'n_classes': len(m['encoder'].classes_),
        'algorithm': 'Random Forest',
    }


def _is_benign(label):
    return str(label).strip().lower() in ('benign', 'normal', 'benign traffic')


def predict_single(model_id, input_dict):
    """Classify one flow from the manual feature form (faithful per-model pipeline)."""
    m = _get(model_id)
    fc = m['feature_columns']

    # Baseline = per-feature means; override with any user-supplied key features.
    values = dict(m['means'])
    for k, v in (input_dict or {}).items():
        if k in values and v not in (None, ''):
            try:
                values[k] = float(v)
            except (ValueError, TypeError):
                pass

    vec = np.array([values.get(f, 0.0) for f in fc], dtype=float).reshape(1, -1)
    X = m['scaler'].transform(vec) if m['kind'] == 'scaled' else vec

    pred_enc = m['model'].predict(X)
    label = str(m['encoder'].inverse_transform(pred_enc)[0])
    result = {'prediction': label, 'is_attack': not _is_benign(label)}

    if hasattr(m['model'], 'predict_proba'):
        probs = m['model'].predict_proba(X)[0]
        classes = list(map(str, m['encoder'].classes_))
        top = sorted(zip(classes, probs), key=lambda x: x[1], reverse=True)[:6]
        result['confidence'] = round(float(np.max(probs)) * 100, 2)
        result['probabilities'] = [{'class': c, 'prob': round(float(p) * 100, 2)} for c, p in top]
    return result


def _align_dataframe(m, df):
    """Reindex an arbitrary CSV to the model's feature_columns, filling gaps with means."""
    fc = m['feature_columns']
    df = df.copy()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    for f in fc:
        if f not in df.columns:
            df[f] = m['means'].get(f, 0.0)
        else:
            df[f] = pd.to_numeric(df[f], errors='coerce')
    df = df[fc]
    # Fill remaining NaNs with the per-feature baseline mean.
    df = df.fillna(value={f: m['means'].get(f, 0.0) for f in fc})
    return df


def predict_csv(model_id, file_stream, max_rows=1_000_000):
    """Bulk-classify an uploaded CSV. Returns a distribution summary + sample rows."""
    m = _get(model_id)
    df = pd.read_csv(file_stream, nrows=max_rows + 1, low_memory=False, on_bad_lines='skip')
    truncated = len(df) > max_rows
    if truncated:
        df = df.iloc[:max_rows]
    if df.empty:
        raise ValueError('The uploaded CSV contains no data rows.')

    X = _align_dataframe(m, df)
    Xt = m['scaler'].transform(X) if m['kind'] == 'scaled' else X.values
    preds = m['encoder'].inverse_transform(m['model'].predict(Xt))

    total = len(preds)
    counts = {}
    for p in preds:
        counts[str(p)] = counts.get(str(p), 0) + 1
    benign = sum(c for k, c in counts.items() if _is_benign(k))
    attacks = total - benign
    distribution = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)

    sample = [{'row': i + 1, 'prediction': str(p), 'is_attack': not _is_benign(p)}
              for i, p in enumerate(preds[:100])]

    return {
        'total_rows': total,
        'benign_count': benign,
        'attack_count': attacks,
        'truncated': truncated,
        'distribution': [{'class': c, 'count': n, 'pct': round(n / total * 100, 2)}
                         for c, n in distribution],
        'sample': sample,
    }


# ── Real-time chunked bulk analysis (ports the desktop Bulk Analysis dashboard) ─
def count_rows(path):
    """Fast row count (minus header) for an accurate progress bar."""
    with open(path, 'rb') as f:
        n = sum(buf.count(b'\n') for buf in iter(lambda: f.read(1024 * 1024), b''))
    return max(n - 1, 0)


def _threat_buckets(class_counts):
    """Bucket predicted classes into LOW/MEDIUM/HIGH/CRITICAL (desktop-app rules)."""
    low = sum(c for k, c in class_counts.items() if _is_benign(k))
    med = high = crit = 0
    for name, c in class_counts.items():
        if _is_benign(name):
            continue
        n = name.lower()
        if 'ddos' in n or 'critical' in n or 'bot' in n:
            crit += c
        elif 'dos' in n or 'slowloris' in n or 'goldeneye' in n:
            high += c
        else:
            med += c
    return {'LOW': low, 'MEDIUM': med, 'HIGH': high, 'CRITICAL': crit}


def _system_threat(total, benign):
    """Overall threat level from the attack ratio (desktop-app thresholds)."""
    ratio = (total - benign) / total if total else 0.0
    if ratio == 0:
        return 'LOW'
    if ratio <= 0.05:
        return 'MEDIUM'
    if ratio <= 0.20:
        return 'HIGH'
    return 'CRITICAL'


def analyze_csv_chunks(model_id, path, total_rows, chunksize=20000):
    """Generator: classify the CSV in chunks, yielding cumulative dashboard stats
    after each chunk so the UI can update in real time. Bounds memory to one chunk."""
    m = _get(model_id)
    fc = m['feature_columns']
    imp = pd.Series(m['model'].feature_importances_, index=fc).nlargest(1)
    top_name, top_imp = imp.index[0], float(imp.values[0])

    class_counts, proto = {}, {'TCP': 0, 'UDP': 0, 'Other': 0}
    processed, sum_dur, sum_byts = 0, 0.0, 0.0

    for chunk in pd.read_csv(path, chunksize=chunksize, low_memory=False, on_bad_lines='skip'):
        X = _align_dataframe(m, chunk)
        Xt = m['scaler'].transform(X) if m['kind'] == 'scaled' else X.values
        preds = m['encoder'].inverse_transform(m['model'].predict(Xt))
        for p in preds:
            class_counts[str(p)] = class_counts.get(str(p), 0) + 1
        for v in X['protocol'].values:
            if v in (6, 6.0):
                proto['TCP'] += 1
            elif v in (17, 17.0):
                proto['UDP'] += 1
            else:
                proto['Other'] += 1
        if 'flow_duration' in X:
            sum_dur += float(X['flow_duration'].sum())
        if 'flow_byts_s' in X:
            sum_byts += float(X['flow_byts_s'].sum())
        processed += len(preds)

        benign = sum(c for k, c in class_counts.items() if _is_benign(k))
        denom = total_rows or processed
        yield {
            'processed': processed,
            'total': denom,
            'pct': round(min(processed / denom * 100, 100), 1),
            'total_rows': processed,
            'benign': benign,
            'attacks': processed - benign,
            'benign_pct': round(benign / processed * 100, 1),
            'attack_pct': round((processed - benign) / processed * 100, 1),
            'system_threat': _system_threat(processed, benign),
            'threat_dist': _threat_buckets(class_counts),
            'proto_dist': dict(proto),
            'top_feature': top_name,
            'top_feature_imp': round(top_imp * 100, 2),
            'mean_flow_dur': round(sum_dur / processed, 2),
            'mean_bandwidth': round(sum_byts / processed, 2),
            'distribution': sorted(class_counts.items(), key=lambda kv: kv[1], reverse=True),
        }


def build_report_text(model_id, final):
    """Build the Gemini statistics text from the accumulated bulk-analysis stats."""
    m = _get(model_id)
    top5 = pd.Series(m['model'].feature_importances_, index=m['feature_columns']).nlargest(5)
    total, benign, attacks = final['total_rows'], final['benign'], final['attacks']
    lines = [
        '=' * 60, 'NETWORK TRAFFIC ANALYSIS REPORT',
        f"Model: {MODELS[model_id]['label']} (Random Forest)", '=' * 60, '',
        f'Total Rows Analyzed: {total}',
        f'Benign Traffic: {benign} ({final["benign_pct"]}%)',
        f'Attack Traffic: {attacks} ({final["attack_pct"]}%)',
        f'System Threat Level: {final["system_threat"]}', '',
        'Attack Type Distribution:',
    ]
    for k, c in final['distribution']:
        if not _is_benign(k):
            lines.append(f'  {k}: {c} rows ({c / total * 100:.1f}%)')
    lines += ['', 'Top 5 Most Important Features (model importance):']
    for f, v in top5.items():
        lines.append(f'  {f}: {v:.4f}')
    lines += ['', 'Statistical Summary:',
              f'  Mean flow duration: {final["mean_flow_dur"]:.2f} us',
              f'  Mean bandwidth: {final["mean_bandwidth"]:.2f} B/s']
    return '\n'.join(lines)


# ── Gemini Word-report pipeline (ports cicids_app_complete.py behaviour) ───────
def _build_statistics_text(model_id, df, preds):
    m = _get(model_id)
    preds = np.asarray([str(p) for p in preds])
    classes, counts = np.unique(preds, return_counts=True)
    class_counts = dict(zip(classes.tolist(), counts.tolist()))
    total = len(preds)
    benign = sum(c for k, c in class_counts.items() if _is_benign(k))
    attacks = total - benign

    importances = pd.Series(m['model'].feature_importances_, index=m['feature_columns'])
    top = importances.nlargest(5)

    lines = [
        '=' * 60, 'NETWORK TRAFFIC ANALYSIS REPORT',
        f"Model: {MODELS[model_id]['label']} (Random Forest)", '=' * 60, '',
        f'Total Rows Analyzed: {total}',
        f'Benign Traffic: {benign} ({benign / total * 100:.1f}%)',
        f'Attack Traffic: {attacks} ({attacks / total * 100:.1f}%)', '',
        'Attack Type Distribution:',
    ]
    for k, c in sorted(class_counts.items(), key=lambda kv: kv[1], reverse=True):
        if not _is_benign(k):
            lines.append(f'  {k}: {c} rows ({c / total * 100:.1f}%)')
    lines += ['', 'Top 5 Most Important Features (model importance):']
    for f, imp in top.items():
        lines.append(f'  {f}: {imp:.4f}')
    return '\n'.join(lines)


def call_gemini_api(statistical_report):
    """Send the statistics to Gemini and return Markdown (ports app behaviour)."""
    try:
        from google import genai
        from google.genai import types
    except ImportError:
        raise RuntimeError('google-genai not installed. Run: pip install google-genai')

    client = genai.Client(api_key=get_gemini_api_key())

    # Inject the current system date so the generated report is always dated
    # correctly instead of the model guessing. (C# equivalent: DateTime.Now.ToString("yyyy-MM-dd"))
    current_date = datetime.now().strftime('%Y-%m-%d')
    dated_system_prompt = (f"{GEMINI_SYSTEM_PROMPT}\n\n"
                           f"Report Date: {current_date}. Use this exact date as the report "
                           f"date in the Executive Summary and document header; do not infer "
                           f"or invent any other date.")

    prompt = (f"{dated_system_prompt}\n\n"
              f"Report Date: {current_date}\n\n"
              "====================================\n"
              "Network Traffic Analysis Stats:\n"
              "====================================\n\n"
              f"{statistical_report}\n\n"
              "====================================\n"
              "Now, write the technical security report:\n"
              "====================================")

    # Try several current flash models; retry transient 503/429 with backoff.
    models_to_try = ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-flash-latest']
    max_retries = 3
    last_error = None
    for model_name in models_to_try:
        for attempt in range(max_retries):
            try:
                resp = client.models.generate_content(
                    model=model_name, contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=dated_system_prompt, temperature=0.2),
                )
                if resp.text:
                    return resp.text
                raise RuntimeError('Gemini returned an empty response.')
            except Exception as e:
                last_error = e
                msg = str(e).lower()
                transient = any(s in msg for s in
                                ('503', '429', 'high demand', 'unavailable', 'temporar', 'overloaded'))
                if transient and attempt < max_retries - 1:
                    time.sleep(2 * (attempt + 1))   # 2s, 4s backoff
                    continue
                break   # non-transient (or out of retries) → next model
    raise RuntimeError(f'Gemini API error after retries/fallbacks: {last_error}')


def markdown_to_docx(markdown_text, output):
    """Convert Markdown to a formatted DOCX (path or file-like). Ports app behaviour."""
    from docx import Document
    from docx.enum.text import WD_PARAGRAPH_ALIGNMENT

    doc = Document()
    doc.add_heading('Digital Forensics & Network Traffic Analysis Report (CICIDS2017)', level=0)
    for raw in markdown_text.split('\n'):
        line = raw.rstrip()
        if not line.strip():
            doc.add_paragraph()
            continue
        if line.startswith('# '):
            p = doc.add_heading(line[2:].strip(), level=1)
            p.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER
        elif line.startswith('## '):
            doc.add_heading(line[3:].strip(), level=2)
        elif line.startswith('### '):
            doc.add_heading(line[4:].strip(), level=3)
        elif line.startswith(('- ', '* ')):
            doc.add_paragraph(line[2:].strip(), style='List Bullet')
        elif re.match(r'^\d+\.\s', line):
            mt = re.match(r'^(\d+)\.\s(.+)', line)
            doc.add_paragraph(mt.group(2).strip() if mt else line, style='List Number')
        else:
            doc.add_paragraph(line)
    doc.save(output)


def generate_report(model_id, file_stream, max_rows=1_000_000):
    """Full pipeline: CSV → classify → statistics → Gemini → DOCX bytes + summary."""
    m = _get(model_id)
    df = pd.read_csv(file_stream, nrows=max_rows + 1, low_memory=False, on_bad_lines='skip')
    truncated = len(df) > max_rows
    if truncated:
        df = df.iloc[:max_rows]
    if df.empty:
        raise ValueError('The uploaded CSV contains no data rows.')

    X = _align_dataframe(m, df)
    Xt = m['scaler'].transform(X) if m['kind'] == 'scaled' else X.values
    preds = m['encoder'].inverse_transform(m['model'].predict(Xt))

    stats_text = _build_statistics_text(model_id, df, preds)
    md = call_gemini_api(stats_text)
    bio = BytesIO()
    markdown_to_docx(md, bio)
    bio.seek(0)

    total = len(preds)
    benign = sum(1 for p in preds if _is_benign(p))
    return bio, {'total_rows': total, 'attack_count': total - benign,
                 'benign_count': benign, 'truncated': truncated}
