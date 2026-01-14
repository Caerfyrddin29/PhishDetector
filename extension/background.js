chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
    if (req.type === 'SCAN') {
        fetch('http://127.0.0.1:5001/analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(req)
        })
        .then(r => r.json())
        .then(data => {
            chrome.storage.local.get(['scanned', 'blocked'], (s) => {
                chrome.storage.local.set({
                    scanned: (s.scanned || 0) + 1,
                    blocked: (s.blocked || 0) + (data.phishing ? 1 : 0)
                });
            });
            sendResponse(data);
        })
        .catch(() => sendResponse({error: true, reasons: ["Backend Offline"]}));
        return true; 
    }
    
    // Forward scan results to popup
    if (req.type === 'SCAN_RESULT') {
        // This will be picked up by popup.js
        chrome.runtime.sendMessage(req);
    }
});