# My Phishing Detector Web App
# This is the backend server that talks to the browser extension
from flask import Flask, request, jsonify
from flask_cors import CORS
from analyzer import analyzer
from config import Config

app = Flask(__name__)
CORS(app)

@app.route('/test', methods=['GET'])
def test():
    """
    Just a simple test to see if the server is working
    """
    return jsonify({"status": "ok", "message": "Backend is running"})

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    This is where the magic happens - analyze emails for phishing!
    """
    try:
        # Get the data from the browser extension
        data = request.json
        if not data:
            return jsonify({"error": "No JSON"}), 400
            
        # Run our phishing detector
        result = analyzer.analyze(
            body=data.get('body', ''),
            links=data.get('links', []),
            metadata=data.get('metadata', {}),
            sender=data.get('sender', '')
        )
        return jsonify(result)
    except Exception as e:
        # If something goes wrong, return an error but don't crash
        return jsonify({"error": str(e), "phishing": False, "score": 0}), 500

if __name__ == '__main__':
    """
    Start the web server!
    Using the port from our config file
    """
    print("Starting Phishing Detector Server...")
    print(f"Server will run on http://{Config.HOST}:{Config.PORT}")
    app.run(host=Config.HOST, port=Config.PORT, debug=True)
