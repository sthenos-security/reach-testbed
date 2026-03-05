# ============================================================================
# REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
# CWE-918 (SSRF), CWE-611 (XXE), CWE-502 (Deserialization)
# ============================================================================
from flask import Flask, request, jsonify
import requests as http_requests
import pickle
import yaml
import xml.etree.ElementTree as ET
import base64

app = Flask(__name__)

# ============================================================================
# REACHABLE: CWE-918 — SSRF
# ============================================================================
@app.route('/api/fetch', methods=['POST'])
def fetch_url():
    url = request.json.get('url', '')
    resp = http_requests.get(url, timeout=5)
    return jsonify({'status': resp.status_code, 'body': resp.text[:1000]})

@app.route('/api/webhook/test', methods=['POST'])
def test_webhook():
    callback_url = request.json.get('callback', '')
    http_requests.post(callback_url, json={'event': 'test'}, timeout=5)
    return jsonify({'status': 'sent'})

@app.route('/api/image/proxy', methods=['GET'])
def proxy_image():
    img_url = request.args.get('src', '')
    resp = http_requests.get(img_url, timeout=10, stream=True)
    return resp.content, 200, {'Content-Type': resp.headers.get('Content-Type', 'image/png')}

# ============================================================================
# REACHABLE: CWE-611 — XML External Entity (XXE)
# ============================================================================
@app.route('/api/xml/parse', methods=['POST'])
def parse_xml():
    xml_data = request.get_data()
    # BAD: etree.fromstring with resolve_entities (default in lxml)
    from lxml import etree as lxml_etree
    parser = lxml_etree.XMLParser(resolve_entities=True)
    doc = lxml_etree.fromstring(xml_data, parser)
    return jsonify({'root': doc.tag, 'text': doc.text or ''})

@app.route('/api/xml/config', methods=['POST'])
def parse_config_xml():
    xml_data = request.get_data()
    # BAD: xml.etree doesn't block entity expansion by default
    root = ET.fromstring(xml_data)
    config = {child.tag: child.text for child in root}
    return jsonify(config)

# ============================================================================
# REACHABLE: CWE-502 — Unsafe Deserialization
# ============================================================================
@app.route('/api/session/load', methods=['POST'])
def load_session():
    data = request.get_data()
    # BAD: pickle.loads on untrusted data — arbitrary code execution
    session = pickle.loads(data)
    return jsonify({'session': str(session)})

@app.route('/api/config/import', methods=['POST'])
def import_config():
    yaml_data = request.get_data().decode()
    # BAD: yaml.load without SafeLoader — code execution via !!python/object
    config = yaml.load(yaml_data)
    return jsonify({'config': config})

@app.route('/api/data/decode', methods=['POST'])
def decode_data():
    b64_data = request.json.get('data', '')
    raw = base64.b64decode(b64_data)
    # BAD: pickle on base64-decoded user input
    obj = pickle.loads(raw)
    return jsonify({'result': str(obj)})

# ============================================================================
# UNREACHABLE variants
# ============================================================================
def _dead_ssrf():
    http_requests.get("http://169.254.169.254/latest/meta-data/")

def _dead_pickle():
    pickle.loads(b"\x80\x03cbuiltins\neval\nq\x00X\x05\x00\x00\x00helloq\x01\x85q\x02Rq\x03.")

def _dead_xxe():
    from lxml import etree as lxml_etree
    lxml_etree.fromstring(b"<root>&xxe;</root>", lxml_etree.XMLParser(resolve_entities=True))

if __name__ == '__main__':
    app.run(port=5004)
