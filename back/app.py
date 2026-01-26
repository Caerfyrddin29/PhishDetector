from flask import Flask, request, jsonify
from flask_cors import CORS
from analyzer import analyzer
from config import Config

app = Flask(__name__)
CORS(app)

@app.route('/test', methods=['GET'])
def test():
    return jsonify({"status": "ok", "message": "Backend is running"})

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No JSON"}), 400
            
        result = analyzer.analyze(
            body=data.get('body', ''),
            links=data.get('links', []),
            metadata=data.get('metadata', {}),
            sender=data.get('sender', '')
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e), "phishing": False, "score": 0}), 500

if __name__ == '__main__':
    # Using Unified Port from Config
    app.run(host=Config.HOST, port=Config.PORT, debug=True)
