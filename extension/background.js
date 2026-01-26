chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
    if (req.type === 'SCAN') {
        // Port 5001 to match both app.py and Config
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3000); // Reduced to 3 second timeout
        
        fetch('http://127.0.0.1:5001/analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(req),
            signal: controller.signal
        })
        .then(r => {
            clearTimeout(timeoutId);
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            return r.json();
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
        return true; 
    }
});
