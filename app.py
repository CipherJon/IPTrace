from flask import Flask, render_template, jsonify, request
from ip_trace import IPLookupService
import asyncio
import re
from functools import wraps

app = Flask(__name__)
ip_service = IPLookupService()

def is_valid_ip(ip):
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # IPv6 pattern (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    
    return bool(re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip))

def async_route(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))
    return wrapped

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/lookup/<ip>')
@async_route
async def lookup_ip(ip):
    if not is_valid_ip(ip):
        return jsonify({'error': 'Invalid IP address format'}), 400
    
    try:
        result = await ip_service.lookup_ip(ip)
        if not result['sources']:
            return jsonify({'error': 'No data available for this IP address'}), 404
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True) 