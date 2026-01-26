function createActionBanner(data, senderEmail) {
    const old = document.getElementById('phish-shield-banner');
    if (old) old.remove();

    const banner = document.createElement('div');
    banner.id = 'phish-shield-banner';
    const isDangerous = data.phishing;
    const color = isDangerous ? '#d93025' : '#188038';
    
    banner.style.cssText = `position:fixed; top:70px; right:20px; z-index:9999999; width:350px; background:white; border-radius:12px; box-shadow:0 8px 32px rgba(0,0,0,0.25); border-top:8px solid ${color}; padding:15px; font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; transition: all 0.3s ease;`;

    banner.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:flex-start;">
            <div>
                <b style="color:${color}; font-size:16px;">${isDangerous ? '🚨 HIGH RISK DETECTED' : '🛡️ EMAIL VERIFIED'}</b>
                <div style="font-size:12px; color:#5f6368; margin-top:2px;">Risk Score: ${data.score}/100</div>
            </div>
            <button id="close-sh" style="border:none; background:none; cursor:pointer; color:#5f6368;">✕</button>
        </div>
        <div style="margin-top:12px; font-size:13px; color:#3c4043; max-height:100px; overflow-y:auto;">
            ${data.reasons.map(r => `<div style="margin-bottom:4px;">• ${r}</div>`).join('')}
        </div>
        <div style="display:flex; gap:8px; margin-top:15px; border-top:1px solid #eee; padding-top:10px;">
            <button id="trust-btn" style="flex:1; padding:8px; border-radius:6px; border:1px solid #188038; background:white; color:#188038; cursor:pointer; font-weight:bold; font-size:11px;">TRUST SENDER</button>
            <button id="report-btn" style="flex:1; padding:8px; border-radius:6px; border:1px solid #d93025; background:white; color:#d93025; cursor:pointer; font-weight:bold; font-size:11px;">REPORT SENDER</button>
        </div>
    `;

    document.body.appendChild(banner);

    // Auto-close after 8 seconds for safe emails, 15 seconds for dangerous ones
    const autoCloseTime = isDangerous ? 15000 : 8000;
    const autoCloseTimer = setTimeout(() => {
        banner.remove();
    }, autoCloseTime);

    // Button Logic
    document.getElementById('close-sh').onclick = () => {
        clearTimeout(autoCloseTimer);
        banner.remove();
    };
    
    document.getElementById('trust-btn').onclick = () => {
        clearTimeout(autoCloseTimer);
        if (typeof chrome !== 'undefined' && chrome.storage) {
            chrome.storage.local.get(['trustedList'], (res) => {
                const list = res.trustedList || [];
                if (!list.includes(senderEmail)) list.push(senderEmail);
                chrome.storage.local.set({trustedList: list}, () => {
                    alert("Sender Added to Trusted List ✅");
                    banner.remove();
                });
            });
        } else {
            alert("Extension API error - please reload extension");
            banner.remove();
        }
    };
    
    document.getElementById('report-btn').onclick = () => {
        clearTimeout(autoCloseTimer);
        if (typeof chrome !== 'undefined' && chrome.storage) {
            chrome.storage.local.get(['reportedList'], (res) => {
                const list = res.reportedList || [];
                if (!list.includes(senderEmail)) list.push(senderEmail);
                chrome.storage.local.set({reportedList: list}, () => {
                    alert("Sender Reported & Blocked 🚨");
                    banner.remove();
                });
            });
        } else {
            alert("Extension API error - please reload extension");
            banner.remove();
        }
    };
}

function init() {
    if (document.getElementById('scan-control')) return;
    const btn = document.createElement('div');
    btn.id = 'scan-control';
    btn.innerHTML = '🛡️ Scan Safety';
    btn.style.cssText = 'position:fixed; bottom:30px; right:30px; z-index:9999; padding:14px 24px; background:#1a73e8; color:white; border-radius:50px; cursor:pointer; font-weight:bold; box-shadow:0 4px 12px rgba(0,0,0,0.3);';

    btn.onclick = async () => {
        // Try multiple selectors for different email providers
        let container = document.querySelector('.a3s.aiL') || 
                       document.querySelector('[role="main"] .ii.gt') ||
                       document.querySelector('.message-body') ||
                       document.querySelector('[data-message-body]') ||
                       document.querySelector('div[role="article"]') ||
                       document.body;
        
        // Try multiple sender selectors
        let senderElement = document.querySelector('.gD') ||
                            document.querySelector('[email]') ||
                            document.querySelector('.sender') ||
                            document.querySelector('[data-email]');
        
        const senderEmail = senderElement ? 
                           (senderElement.getAttribute('email') || 
                            senderElement.getAttribute('data-email') || 
                            senderElement.innerText.match(/[\w\.-]+@[\w\.-]+\.\w+/)?.[0] || '') : '';

        if (!container) {
            console.error("PhishDetector: Could not find email container");
            return alert("Could not find email content. Please open an email first.");
        }
        
        // Get email content and focus on suspicious parts
        let fullText = container.innerText;
        
        // Extract most suspicious sections (first 200 chars + any lines with scam keywords)
        let suspiciousKeywords = ['cash', 'money', 'earn', 'click here', 'urgent', 'limited time', 'free', 'prize', 'profit', 'bonus'];
        let highRiskKeywords = ['verify', 'account', 'password', 'suspended', 'login', 'security', 'alert', 'confirm'];
        let lines = fullText.split('\n');
        let suspiciousLinesArray = lines.filter(line => 
            suspiciousKeywords.some(keyword => line.toLowerCase().includes(keyword))
        );
        let highRiskLinesArray = lines.filter(line => 
            highRiskKeywords.some(keyword => line.toLowerCase().includes(keyword))
        );
        let suspiciousLines = suspiciousLinesArray.join('\n');
        
        // Calculate frontend risk score for better correlation
        let frontendScore = (suspiciousLinesArray.length * 5) + (highRiskLinesArray.length * 8);
        
        // Combine first part with suspicious sections
        let focusedBody = fullText.substring(0, 200) + '\n' + suspiciousLines;
        
        console.log("PhishDetector Enhanced Debug:");
        console.log("Full text length:", fullText.length);
        console.log("Focused text length:", focusedBody.length);
        console.log("Suspicious lines found:", suspiciousLinesArray.length);
        console.log("High-risk lines found:", highRiskLinesArray.length);
        console.log("Frontend risk score:", frontendScore);
        console.log("Sender:", senderEmail);
        console.log("Body preview:", focusedBody.substring(0, 200));
        
        // Check if chrome extension API is available
        if (typeof chrome === 'undefined' || !chrome.storage) {
            console.error("PhishDetector: Chrome extension API not available");
            return alert("Extension error: Please reload the extension or check permissions.");
        }
        
        // Check local storage for reputation before sending to server
        chrome.storage.local.get(['trustedList', 'reportedList'], (storage) => {
            const isTrusted = (storage.trustedList || []).includes(senderEmail);
            const isReported = (storage.reportedList || []).includes(senderEmail);

            btn.innerText = '🔍 Checking...';
            btn.style.background = '#fbbc04'; // Yellow during scanning
            
            const startTime = Date.now();
            
            const links = Array.from(container.querySelectorAll('a')).map(a => ({
                text: a.innerText, href: a.href, isHidden: window.getComputedStyle(a).opacity === "0"
            }));

            chrome.runtime.sendMessage({
                type: 'SCAN',
                body: focusedBody,  // Send focused content instead of full text
                sender: senderEmail,
                links: links,
                metadata: {
                    isTrusted, isReported,
                    imageCount: container.querySelectorAll('img').length,
                    textLength: focusedBody.length  // Use focused length
                }
            }, (res) => {
                const scanTime = Date.now() - startTime;
                btn.innerText = '🛡️ Scan Safety';
                btn.style.background = '#1a73e8'; // Reset to original color
                
                if (res.error) {
                    console.log(`Scan failed after ${scanTime}ms:`, res.reasons);
                    return alert(`Scan failed: ${res.reasons.join(', ')}`);
                }
                
                console.log(`Scan completed in ${scanTime}ms`);
                createActionBanner(res, senderEmail);
                
                // Update scan statistics
                chrome.storage.local.get(['scanned', 'blocked'], (storage) => {
                    const stats = {
                        scanned: (storage.scanned || 0) + 1,
                        blocked: (storage.blocked || 0) + (res.phishing ? 1 : 0)
                    };
                    chrome.storage.local.set(stats);
                    
                    // Update score history directly
                    chrome.storage.local.get(['scoreHistory'], (historyRes) => {
                        let history = historyRes.scoreHistory || [];
                        history.push(res.score);
                        // Keep only last 50 scores
                        if (history.length > 50) {
                            history = history.slice(-50);
                        }
                        chrome.storage.local.set({ scoreHistory: history });
                    });
                });
                
                if (res.phishing) {
                    container.querySelectorAll('a').forEach(a => {
                        if (res.malicious_urls.includes(a.href)) a.style.border = "2px dashed red";
                    });
                }
            });
        });
    };
    document.body.appendChild(btn);
}
setInterval(init, 2000);
