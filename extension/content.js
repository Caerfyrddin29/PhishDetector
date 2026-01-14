function highlightThreats(malicious_urls) {
    document.querySelectorAll('.a3s.aiL a').forEach(a => {
        if (malicious_urls.includes(a.href)) {
            a.style.cssText = "background:#ffe8e8!important; border:2px dashed #d93025!important; padding:2px; border-radius:4px;";
            a.setAttribute('data-threat', 'true');
        }
    });
}

function createAlert(data) {
    const old = document.getElementById('phish-notif');
    if (old) old.remove();
    
    const div = document.createElement('div');
    div.id = 'phish-notif';
    const isPhishing = data.phishing;
    const score = data.score || 0;
    const language = data.language || 'en';
    
    // Set colors based on score
    let color, bgColor, icon, status;
    if (score >= 70) {
        color = '#d93025';
        bgColor = '#ffe8e8';
        icon = '🚨';
        status = 'PHISHING DETECTED';
    } else if (score >= 30) {
        color = '#fbbc04';
        bgColor = '#fef7e0';
        icon = '⚠️';
        status = 'SUSPICIOUS EMAIL';
    } else {
        color = '#1e8e3e';
        bgColor = '#e8f5e8';
        icon = '🛡️';
        status = 'EMAIL SECURE';
    }
    
    div.style.cssText = `position:fixed; top:25px; right:25px; z-index:2147483647; width:420px; padding:20px; background:${bgColor}; border-left:8px solid ${color}; border-radius:12px; box-shadow:0 12px 40px rgba(0,0,0,0.3); font-family:system-ui,-apple-system,sans-serif;`;
    
    // Format reasons for better readability
    const formattedReasons = data.reasons.slice(0, 5).map(reason => {
        // Clean up technical terms for user display
        return reason
            .replace(/Brand Impersonation/gi, 'Brand impersonation')
            .replace(/Visual Spoofing/gi, 'Visual spoofing')
            .replace(/Blacklisted Domain/gi, 'Known phishing domain')
            .replace(/Masked URL/gi, 'Hidden link destination')
            .replace(/Pressure keywords/gi, 'Suspicious keywords');
    });
    
    div.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
            <div style="font-weight:900; color:${color}; font-size:18px;">
                ${icon} ${status}
            </div>
            <div style="text-align: right;">
                <div style="font-weight: bold; color: ${color}; font-size: 24px;">
                    ${score}/100
                </div>
                <div style="font-size: 10px; color: #666; text-transform: uppercase;">
                    ${language} detected
                </div>
            </div>
        </div>
        <div style="font-size:13px; color:#555; line-height:1.6; margin-bottom: 15px;">
            ${formattedReasons.map(r => `• ${r}`).join('<br>')}
        </div>
        ${data.malicious_urls && data.malicious_urls.length > 0 ? `
            <div style="margin-bottom: 15px;">
                <div style="font-weight: bold; font-size: 12px; color: #d93025; margin-bottom: 5px;">⚠️ MALICIOUS URLS DETECTED:</div>
                ${data.malicious_urls.map(url => `<div style="font-size: 11px; color: #666; word-break: break-all; background: #ffe8e8; padding: 4px 8px; border-radius: 4px; margin: 2px 0;">${url}</div>`).join('')}
            </div>
        ` : ''}
        <div style="display: flex; justify-content: space-between; align-items: center; font-size:11px; color:#888;">
            <div>Auto-dismiss in <span id="countdown">8</span> seconds</div>
            <div style="font-weight:bold;">PHISHDETECTOR PRO v2.0</div>
        </div>
    `;
    
    document.body.appendChild(div);
    
    // Auto-dismiss countdown
    let countdown = 8;
    const countdownEl = div.querySelector('#countdown');
    const countdownInterval = setInterval(() => {
        countdown--;
        if (countdownEl) countdownEl.innerText = countdown;
        
        if (countdown <= 0) {
            clearInterval(countdownInterval);
            div.remove();
        }
    }, 1000);
    
    // Click to dismiss
    div.addEventListener('click', () => {
        clearInterval(countdownInterval);
        div.remove();
    });
}

function init() {
    if (document.getElementById('phish-main-btn')) return;
    const btn = document.createElement('button');
    btn.id = 'phish-main-btn';
    btn.innerText = '🛡️ Scan Safety';
    btn.style.cssText = 'position:fixed; bottom:30px; right:30px; z-index:9999; padding:14px 24px; background:#1a73e8; color:white; border-radius:30px; border:none; cursor:pointer; font-weight:bold; box-shadow:0 4px 15px rgba(0,0,0,0.2); transition:transform 0.2s;';
    
    btn.onclick = () => {
        const emailDiv = document.querySelector('.a3s.aiL');
        if (!emailDiv) return alert("Please open a Gmail email first.");
        
        const links = Array.from(emailDiv.querySelectorAll('a')).map(a => ({
            text: a.innerText, href: a.href, isHidden: window.getComputedStyle(a).opacity === "0"
        }));

        // Extract sender information
        let sender = '';
        let senderIP = '';
        try {
            const senderElement = document.querySelector('.gD span[email]') || document.querySelector('.go span[email]');
            if (senderElement) {
                sender = senderElement.getAttribute('email') || senderElement.innerText;
            }
        } catch (e) {
            console.log('Could not extract sender info');
        }

        // Count attachments
        const attachments = document.querySelectorAll('.aQH span.aV3') || document.querySelectorAll('[data-tooltip*="attachment"]');
        const hasAttachments = attachments.length > 0;

        btn.innerText = '🔍 Analyzing...';
        chrome.runtime.sendMessage({
            type: 'SCAN', 
            body: emailDiv.innerText, 
            links: links,
            metadata: { 
                imageCount: emailDiv.querySelectorAll('img').length, 
                textLength: emailDiv.innerText.length,
                hasHiddenLinks: links.some(l => l.isHidden),
                sender: sender,
                senderIP: senderIP,
                hasAttachments: hasAttachments,
                attachmentCount: attachments.length
            }
        }, (res) => {
            btn.innerText = '🛡️ Scan Safety';
            if (res.error) {
                alert("Backend Offline! Please start backend server.");
                return;
            }
            
            // Send score to popup for tracking
            chrome.runtime.sendMessage({
                type: 'SCAN_RESULT',
                score: res.score || 0
            });
            
            createAlert(res);
            if (res.phishing) highlightThreats(res.malicious_urls);
        });
    };
    document.body.appendChild(btn);
}
setInterval(init, 2000);