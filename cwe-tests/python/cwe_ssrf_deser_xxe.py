# ============================================================================
# REACHABLE TEST — DO NOT USE IN PRODUCTION
# CWE-918 (SSRF), CWE-611 (XXE), CWE-502 (Deserialization)
# ============================================================================
from flask import Flask, request, jsonify
import requests as http_requests
import pickle
import yaml
import base64
from lxml import etree

app = Flask(__name__)

# ── REACHABLE: CWE-918 — SSRF (user-controlled URL) ────────────────────────
@app.route('/api/fetch', methods=['POST'])
def fetch_url():
    url = request.json.get('url', '')
    resp = http_requests.get(url, timeout=5)
    return jsonify({'status': resp.status_code, 'body': resp.text[:1000]})

@app.route('/api/webhook/test', methods=['POST'])
def test_webhook():
    callback = request.json.get('callback_url', '')
    http_requests.post(callback, json={'event': 'test'}, timeout=5)
    return jsonify({'sent': True})

@app.route('/api/avatar', methods=['GET'])
def fetch_avatar():
    img_url = request.args.get('url', '')
    resp = http_requests.get(img_url, timeout=10, stream=True)
    return resp.content, 200, {'Content-Type': 'image/png'}

# ── REACHABLE: CWE-611 — XML External Entity (XXE) ─────────────────────────
@app.route('/api/xml/parse', methods=['POST'])
def parse_xml():
    xml_data = request.get_data()
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    tree = etree.fromstring(xml_data, parser)
    return jsonify({'root': tree.tag, 'text': tree.text})

@app.route('/api/xml/transform', methods=['POST'])
def transform_xml():
    xml_data = request.get_data()
    doc = etree.fromstring(xml_data)
    result = etree.tostring(doc, pretty_print=True).decode()
    return jsonify({'result': result})

# ── REACHABLE: CWE-502 — Unsafe Deserialization ────────────────────────────
@app.route('/api/restore', methods=['POST'])
def restore_session():
    data = request.get_data()
    session = pickle.loads(data)
    return jsonify({'user': session.get('user', 'unknown')})

@app.route('/api/import/yaml', methods=['POST'])
def import_yaml():
    raw = request.get_data().decode()
    config = yaml.load(raw, Loader=yaml.Loader)
    return jsonify({'config': str(config)})

@app.route('/api/restore/b64', methods=['POST'])
def restore_b64():
    encoded = request.json.get('data', '')
    obj = pickle.loads(base64.b64decode(encoded))
    return jsonify({'restored': str(obj)})

# ── UNREACHABLE ─────────────────────────────────────────────────────────────
def _dead_ssrf():
    http_requests.get("http://169.254.169.254/latest/meta-data/")

def _dead_pickle():
    pickle.loads(b"\x80\x03cbuiltins\neval\nq\x00X\x0b\x00\x00\x00os.system('id')q\x01\x85q\x02Rq\x03.")

def _dead_xxe():
    etree.fromstring(b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>')

if __name__ == '__main__':
    app.run(port=5004)
