// Background script for my phishing detector extension
// This talks to the backend server

chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
    if (req.type === 'SCAN') {
        // Send the email to our backend server for analysis
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3000); // 3 second timeout
        
        fetch('http://127.0.0.1:5001/analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(req),
            signal: controller.signal
        })
        .then(response => {
            clearTimeout(timeoutId);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return response.json();
        })
        .then(data => {
            sendResponse(data);
        })
        .catch(error => {
            clearTimeout(timeoutId);
            console.error('Scan error:', error);
            if (error.name === 'AbortError') {
                sendResponse({error: true, reasons: ["Request timeout - analysis taking too long"]});
            } else {
                sendResponse({error: true, reasons: ["Backend connection failed"]});
            }
        });
        return true; // Keep the message channel open for async response
    }
});
