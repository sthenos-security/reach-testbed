"""
Main application entrypoint.
This file imports and uses various modules to test reachability detection.
"""
from flask import Flask
from src.cve_reachable import fetch_data
from src.cwe_reachable import render_user_input
from src.secret_reachable import get_api_key

# Note: We do NOT import from dead code modules - they should be unreachable

app = Flask(__name__)

@app.route('/')
def index():
    """Main route - calls reachable functions."""
    # CVE: This calls requests.get() which has CVE-2021-33503
    data = fetch_data("https://api.example.com/data")
    
    # CWE: This has XSS vulnerability
    html = render_user_input("<script>alert('xss')</script>")
    
    # SECRET: This loads a hardcoded API key
    api_key = get_api_key()
    
    return f"Data: {data}, Key: {api_key[:4]}..."

@app.route('/health')
def health():
    """Health check - no vulnerabilities."""
    return "OK"

if __name__ == '__main__':
    app.run(debug=True)
