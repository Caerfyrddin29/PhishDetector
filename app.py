from flask import Flask, request, jsonify
from flask_cors import CORS
from analyzer import analyzer

app = Flask(__name__)
CORS(app)

# Simple test endpoint
@app.route('/test', methods=['GET'])
def test():
    return jsonify({"status": "working"})

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
            
        body = data.get('body', '')
        links = data.get('links', [])
        metadata = data.get('metadata', {})
        
        # Use the advanced analyzer
        result = analyzer.analyze(
            body=body,
            links=links,
            metadata=metadata
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "phishing": False,
            "score": 0,
            "reasons": [f"Server error: {str(e)}"],
            "malicious_urls": []
        }), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=True)
