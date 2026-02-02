// Content script for my phishing detector extension
// This injects the scan button and analyzes emails

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 10000000;
        padding: 16px 20px;
        border-radius: 12px;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        font-weight: 500;
        font-size: 14px;
        box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        animation: notificationSlide 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        backdrop-filter: blur(10px);
        max-width: 300px;
    `;
    
    const colors = {
        success: { bg: '#f0fdf4', border: '#10b981', text: '#065f46' },
        error: { bg: '#fef2f2', border: '#ef4444', text: '#991b1b' },
        warning: { bg: '#fffbeb', border: '#f59e0b', text: '#92400e' },
        info: { bg: '#eff6ff', border: '#3b82f6', text: '#1e40af' }
    };
    
    const theme = colors[type] || colors.info;
    notification.style.background = theme.bg;
    notification.style.border = `1px solid ${theme.border}`;
    notification.style.color = theme.text;
    notification.textContent = message;
    
    const style = document.createElement('style');
    style.textContent = `
        @keyframes notificationSlide {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
    `;
    document.head.appendChild(style);
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'notificationSlide 0.3s cubic-bezier(0.4, 0, 0.2, 1) reverse';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

function createActionBanner(data, senderEmail) {
    // Remove old banner if there is one
    const old = document.getElementById('phish-shield-banner');
    if (old) old.remove();

    // Create the banner
    const banner = document.createElement('div');
    banner.id = 'phish-shield-banner';
    const isDangerous = data.is_phishing;
    const colors = {
        dangerous: {
            primary: '#ef4444',
            background: '#fef2f2',
            border: '#dc2626',
            text: '#991b1b',
            glow: 'rgba(239, 68, 68, 0.3)'
        },
        safe: {
            primary: '#10b981',
            background: '#f0fdf4',
            border: '#059669',
            text: '#065f46',
            glow: 'rgba(16, 185, 129, 0.3)'
        }
    };
    
    const theme = isDangerous ? colors.dangerous : colors.safe;
    
    banner.style.cssText = `
        position: fixed; 
        top: 80px; 
        right: 20px; 
        z-index: 9999999; 
        width: 380px; 
        background: ${theme.background}; 
        border-radius: 16px; 
        box-shadow: 0 20px 40px rgba(0,0,0,0.15), 0 0 0 1px ${theme.border}20; 
        border-left: 4px solid ${theme.primary}; 
        padding: 20px; 
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; 
        transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1); 
        animation: slideIn 0.5s cubic-bezier(0.4, 0, 0.2, 1);
        backdrop-filter: blur(10px);
    `;

    // Add animation keyframes
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from {
                transform: translateX(100%) scale(0.8);
                opacity: 0;
            }
            to {
                transform: translateX(0) scale(1);
                opacity: 1;
            }
        }
        
        @keyframes slideOut {
            from {
                transform: translateX(0) scale(1);
                opacity: 1;
            }
            to {
                transform: translateX(100%) scale(0.8);
                opacity: 0;
            }
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        
        @keyframes shimmer {
            0% { background-position: -200% 0; }
            100% { background-position: 200% 0; }
        }
        
        .phish-banner-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 16px;
        }
        
        .phish-banner-title {
            font-weight: 700;
            font-size: 16px;
            color: ${theme.primary};
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .phish-banner-logo {
            width: 20px;
            height: 20px;
            border-radius: 4px;
        }
        
        .phish-banner-score {
            font-size: 12px;
            color: ${theme.text};
            margin-top: 4px;
            font-weight: 500;
        }
        
        .phish-banner-close {
            border: none;
            background: none;
            cursor: pointer;
            color: ${theme.text};
            font-size: 18px;
            width: 28px;
            height: 28px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
        }
        
        .phish-banner-close:hover {
            background: ${theme.primary}20;
            transform: scale(1.1);
        }
        
        .phish-banner-reasons {
            margin: 16px 0;
            font-size: 13px;
            color: ${theme.text};
            max-height: 120px;
            overflow-y: auto;
            line-height: 1.5;
        }
        
        .phish-banner-reasons::-webkit-scrollbar {
            width: 4px;
        }
        
        .phish-banner-reasons::-webkit-scrollbar-track {
            background: ${theme.primary}10;
            border-radius: 2px;
        }
        
        .phish-banner-reasons::-webkit-scrollbar-thumb {
            background: ${theme.primary}40;
            border-radius: 2px;
        }
        
        .phish-banner-reason-item {
            margin-bottom: 6px;
            padding-left: 16px;
            position: relative;
        }
        
        .phish-banner-reason-item::before {
            content: '•';
            position: absolute;
            left: 0;
            color: ${theme.primary};
            font-weight: bold;
        }
        
        .phish-banner-progress {
            margin: 16px 0;
            height: 6px;
            background: ${theme.primary}20;
            border-radius: 3px;
            overflow: hidden;
            position: relative;
        }
        
        .phish-banner-progress-bar {
            height: 100%;
            background: linear-gradient(90deg, ${theme.primary}, ${theme.border});
            border-radius: 3px;
            transition: width 0.1s linear;
            position: relative;
        }
        
        .phish-banner-progress-bar::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            background-size: 200% 100%;
            animation: shimmer 2s infinite;
        }
        
        .phish-banner-actions {
            display: flex;
            gap: 8px;
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid ${theme.primary}20;
        }
        
        .phish-banner-btn {
            flex: 1;
            padding: 10px 12px;
            border-radius: 8px;
            border: 2px solid ${theme.primary};
            background: white;
            color: ${theme.primary};
            cursor: pointer;
            font-weight: 600;
            font-size: 11px;
            text-align: center;
            transition: all 0.2s ease;
            position: relative;
            overflow: hidden;
        }
        
        .phish-banner-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px ${theme.glow};
        }
        
        .phish-banner-btn:active {
            transform: translateY(0);
        }
        
        .phish-banner-btn.danger {
            border-color: #ef4444;
            color: #ef4444;
        }
        
        .phish-banner-btn.danger:hover {
            background: #ef4444;
            color: white;
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
        }
        
        .phish-banner-btn.success {
            border-color: #10b981;
            color: #10b981;
        }
        
        .phish-banner-btn.success:hover {
            background: #10b981;
            color: white;
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
        }
        
        .phish-banner-btn.warning {
            border-color: #f59e0b;
            color: #f59e0b;
        }
        
        .phish-banner-btn.warning:hover {
            background: #f59e0b;
            color: white;
            box-shadow: 0 4px 12px rgba(245, 158, 11, 0.3);
        }
    `;
    document.head.appendChild(style);

    banner.innerHTML = `
        <div class="phish-banner-header">
            <div>
                <div class="phish-banner-title">
                    <img src="${chrome.runtime.getURL('logo.svg')}" alt="PhishDetector" class="phish-banner-logo">
                    ${isDangerous ? 'HIGH RISK DETECTED' : 'EMAIL VERIFIED'}
                </div>
                <div class="phish-banner-score">Risk Score: ${data.score}/100</div>
            </div>
            <button id="close-sh" class="phish-banner-close">✕</button>
        </div>
        <div class="phish-banner-reasons">
            ${data.reasons.map(r => `<div class="phish-banner-reason-item">${r}</div>`).join('')}
        </div>
        <div class="phish-banner-progress">
            <div id="progress-bar" class="phish-banner-progress-bar"></div>
        </div>
        <div class="phish-banner-actions">
            <button id="trust-btn" class="phish-banner-btn success">TRUST SENDER</button>
            <button id="report-btn" class="phish-banner-btn danger">REPORT SENDER</button>
            <button id="block-domain-btn" class="phish-banner-btn warning">BLOCK DOMAIN</button>
        </div>
    `;

    document.body.appendChild(banner);

    // Auto-close after 10 seconds with animated progress bar
    const autoCloseTime = 10000; // Exactly 10 seconds
    const progressBar = banner.querySelector('#progress-bar');
    let startTime = Date.now();
    let animationFrame;
    
    const updateProgress = () => {
        const elapsed = Date.now() - startTime;
        const remaining = Math.max(0, autoCloseTime - elapsed);
        const percentage = (remaining / autoCloseTime) * 100;
        
        if (progressBar) {
            progressBar.style.width = percentage + '%';
        }
        
        if (remaining > 0) {
            animationFrame = requestAnimationFrame(updateProgress);
        } else {
            removeBannerWithAnimation();
        }
    };
    
    const removeBannerWithAnimation = () => {
        banner.style.animation = 'slideOut 0.4s cubic-bezier(0.4, 0, 0.2, 1)';
        setTimeout(() => {
            if (banner.parentNode) {
                banner.remove();
            }
        }, 400);
    };
    
    const autoCloseTimer = setTimeout(() => {
        cancelAnimationFrame(animationFrame);
        removeBannerWithAnimation();
    }, autoCloseTime);
    
    // Start the animation
    updateProgress();

    // Button clicks
    document.getElementById('close-sh').onclick = () => {
        clearTimeout(autoCloseTimer);
        cancelAnimationFrame(animationFrame);
        removeBannerWithAnimation();
    };
    
    document.getElementById('trust-btn').onclick = () => {
        clearTimeout(autoCloseTimer);
        cancelAnimationFrame(animationFrame);
        if (checkExtensionContext()) {
            safeStorageGet(['trustedList'], (res) => {
                const list = res.trustedList || [];
                if (!list.includes(senderEmail)) list.push(senderEmail);
                safeStorageSet({trustedList: list}, () => {
                    showNotification("Sender Added to Trusted List ✅", 'success');
                    removeBannerWithAnimation();
                });
            });
        } else {
            showNotification("Extension context invalidated. Please reload the page.", 'error');
            removeBannerWithAnimation();
        }
    };
    
    document.getElementById('report-btn').onclick = () => {
        clearTimeout(autoCloseTimer);
        cancelAnimationFrame(animationFrame);
        if (checkExtensionContext()) {
            safeStorageGet(['reportedList'], (res) => {
                const list = res.reportedList || [];
                if (!list.includes(senderEmail)) list.push(senderEmail);
                safeStorageSet({reportedList: list}, () => {
                    showNotification("Sender Reported & Blocked 🚨", 'warning');
                    removeBannerWithAnimation();
                });
            });
        } else {
            showNotification("Extension context invalidated. Please reload the page.", 'error');
            removeBannerWithAnimation();
        }
    };
    
    document.getElementById('block-domain-btn').onclick = () => {
        clearTimeout(autoCloseTimer);
        cancelAnimationFrame(animationFrame);
        const domain = extractDomainFromEmail(senderEmail);
        if (domain) {
            if (checkExtensionContext()) {
                safeStorageGet(['blockedDomains'], (res) => {
                    const domains = res.blockedDomains || [];
                    if (!domains.includes(domain)) {
                        domains.push(domain);
                        safeStorageSet({blockedDomains: domains}, () => {
                            alert(`Domain ${domain} blocked! Future emails will be moved to spam automatically. 🚫`);
                            banner.remove();
                            // Immediately check and move current email to spam if needed
                            checkAndMoveBlockedDomainsToSpam();
                        });
                    } else {
                        alert(`Domain ${domain} is already blocked! 🚫`);
                        banner.remove();
                    }
                });
            } else {
                alert("Extension context invalidated. Please reload the page.");
                banner.remove();
            }
        } else {
            alert("Could not extract domain from email address");
            banner.remove();
        }
    };
}

function checkExtensionContext() {
    try {
        return typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id;
    } catch (e) {
        return false;
    }
}

function safeStorageGet(keys, callback) {
    try {
        if (!checkExtensionContext()) {
            console.warn('Extension context invalidated, using fallback values');
            callback({});
            return;
        }
        chrome.storage.local.get(keys, callback);
    } catch (e) {
        console.warn('Storage access failed:', e);
        callback({});
    }
}

function safeStorageSet(items, callback) {
    try {
        if (!checkExtensionContext()) {
            console.warn('Extension context invalidated, skipping storage update');
            if (callback) callback();
            return;
        }
        chrome.storage.local.set(items, callback);
    } catch (e) {
        console.warn('Storage update failed:', e);
        if (callback) callback();
    }
}

function safeRuntimeSendMessage(message, callback) {
    try {
        if (!checkExtensionContext()) {
            console.warn('Extension context invalidated, cannot send message');
            if (callback) callback({error: true, reasons: ["Extension context invalidated"]});
            return;
        }
        chrome.runtime.sendMessage(message, callback);
    } catch (e) {
        console.warn('Runtime message failed:', e);
        if (callback) callback({error: true, reasons: ["Extension context invalidated"]});
    }
}

function checkAndMoveBlockedDomainsToSpam() {
    safeStorageGet(['blockedDomains', 'autoSpamEnabled'], (res) => {
        if (!res.autoSpamEnabled || !res.blockedDomains || res.blockedDomains.length === 0) {
            return;
        }
        
        // Find all email elements in the current view
        const emailElements = document.querySelectorAll('[data-thread-id], [role="row"], .zA, .y6');
        
        emailElements.forEach(emailElement => {
            try {
                // Extract sender email from various Gmail selectors
                const senderElement = emailElement.querySelector('.go', 'span[email]', '[email]') ||
                                   emailElement.querySelector('.gD') ||
                                   emailElement.querySelector('span[data-email]') ||
                                   emailElement;
                
                const senderEmail = senderElement ? 
                    (senderElement.getAttribute('email') || 
                     senderElement.getAttribute('data-email') || 
                     senderElement.innerText.match(/[\w\.-]+@[\w\.-]+\.\w+/)?.[0] || '') : '';
                
                if (senderEmail) {
                    const domain = senderEmail.split('@')[1]?.toLowerCase();
                    if (domain && res.blockedDomains.includes(domain)) {
                        // Mark email as spam
                        markAsSpam(emailElement, senderEmail, domain);
                    }
                }
            } catch (error) {
                console.log('Error checking email for blocked domain:', error);
            }
        });
    });
}

function markAsSpam(emailElement, senderEmail, domain) {
    // Add visual indicator that this is from a blocked domain
    const spamIndicator = document.createElement('div');
    spamIndicator.style.cssText = `
        background: #ea4335;
        color: white;
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: bold;
        margin-left: 8px;
        display: inline-block;
    `;
    spamIndicator.textContent = '🚫 BLOCKED DOMAIN';
    
    // Try to find the sender element to add the indicator
    const senderElement = emailElement.querySelector('.go, .gD, span[email], [data-email]') || emailElement;
    senderElement.appendChild(spamIndicator);
    
    // Try to find and click the spam/more options button
    const moreButton = emailElement.querySelector('.a4T, .T-Jo, .a3s') ||
                      emailElement.querySelector('[aria-label*="More"], [aria-label*="more"]');
    
    if (moreButton) {
        setTimeout(() => {
            moreButton.click();
            
            // Wait for menu to appear, then click "Report spam"
            setTimeout(() => {
                const spamOption = document.querySelector('[aria-label*="Report spam"], [aria-label*="Spam"], [data-action*="spam"]') ||
                                 document.querySelector('.J-N-Jz, .a4Y, [role="menuitem"]:has-text("Spam")');
                
                if (spamOption) {
                    spamOption.click();
                    console.log(`Auto-moved email from ${domain} to spam`);
                }
            }, 500);
        }, 100);
    }
}

function extractDomainFromEmail(email) {
    const match = email.match(/@([\w\.-]+\.\w+)/);
    return match ? match[1].toLowerCase() : null;
}

function init() {
    // Don't add button if it's already there
    if (document.getElementById('scan-control')) return;
    
    // Check for blocked domains and auto-spam
    checkAndMoveBlockedDomainsToSpam();
    
    // Create the scan button
    const btn = document.createElement('div');
    btn.id = 'scan-control';
    btn.innerHTML = '🛡️ Scan Safety';
    btn.style.cssText = 'position:fixed; bottom:30px; right:30px; z-index:9999; padding:14px 24px; background:#1a73e8; color:white; border-radius:50px; cursor:pointer; font-weight:bold; box-shadow:0 4px 12px rgba(0,0,0,0.3);';

    // What happens when you click the button
    btn.onclick = async () => {
        // Try to find the email content (different email providers use different HTML)
        let container = document.querySelector('.a3s.aiL') || 
                       document.querySelector('[role="main"] .ii.gt') ||
                       document.querySelector('.message-body') ||
                       document.querySelector('[data-message-body]') ||
                       document.querySelector('div[role="article"]') ||
                       document.body;
        
        // Try to find who sent the email
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
        
        // Get the email text
        let fullText = container.innerText;
        
        // Look for suspicious words
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
        
        // Calculate a quick risk score
        let frontendScore = (suspiciousLinesArray.length * 5) + (highRiskLinesArray.length * 8);
        
        // Focus on the suspicious parts
        let focusedBody = fullText.substring(0, 200) + '\n' + suspiciousLines;
        
        console.log("PhishDetector Debug Info:");
        console.log("Full text length:", fullText.length);
        console.log("Focused text length:", focusedBody.length);
        console.log("Suspicious lines found:", suspiciousLinesArray.length);
        console.log("High-risk lines found:", highRiskLinesArray.length);
        console.log("Frontend risk score:", frontendScore);
        console.log("Sender:", senderEmail);
        
        // Check if extension APIs are working
        if (!checkExtensionContext()) {
            console.error("PhishDetector: Chrome extension context invalidated");
            return alert("Extension context invalidated. Please reload the page.");
        }
        
        // Check if user already trusts or reported this sender
        safeStorageGet(['trustedList', 'reportedList'], (storage) => {
            const isTrusted = (storage.trustedList || []).includes(senderEmail);
            const isReported = (storage.reportedList || []).includes(senderEmail);

            // Show we're analyzing
            btn.innerText = '🔍 Checking...';
            btn.style.background = '#fbbc04'; // Yellow during scanning
            
            const startTime = Date.now();
            
            // Get all the links in the email
            const links = Array.from(container.querySelectorAll('a')).map(a => ({
                text: a.innerText, href: a.href, isHidden: window.getComputedStyle(a).opacity === "0"
            }));

            // Send to backend for analysis
            safeRuntimeSendMessage({
                type: 'SCAN',
                body: focusedBody,
                sender: senderEmail,
                links: links,
                metadata: {
                    isTrusted, isReported,
                    imageCount: container.querySelectorAll('img').length,
                    textLength: focusedBody.length
                }
            }, (res) => {
                const scanTime = Date.now() - startTime;
                btn.innerText = '🛡️ Scan Safety';
                btn.style.background = '#1a73e8'; // Reset color
                
                if (res.error) {
                    console.log(`Scan failed after ${scanTime}ms:`, res.reasons);
                    return alert(`Scan failed: ${res.reasons.join(', ')}`);
                }
                
                console.log(`Scan completed in ${scanTime}ms`);
                createActionBanner(res, senderEmail);
                
                // Update statistics
                safeStorageGet(['scanned', 'blocked'], (storage) => {
                    const stats = {
                        scanned: (storage.scanned || 0) + 1,
                        blocked: (storage.blocked || 0) + (res.is_phishing ? 1 : 0)
                    };
                    safeStorageSet(stats);
                    
                    // Update score history
                    safeStorageGet(['scoreHistory'], (historyRes) => {
                        let history = historyRes.scoreHistory || [];
                        history.push(res.score);
                        // Keep only last 50 scores
                        if (history.length > 50) {
                            history = history.slice(-50);
                        }
                        safeStorageSet({ scoreHistory: history });
                    });
                });
                
                // Mark bad links
                if (res.is_phishing) {
                    container.querySelectorAll('a').forEach(a => {
                        if (res.malicious_urls.includes(a.href)) a.style.border = "2px dashed red";
                    });
                }
            });
        });
    };
    document.body.appendChild(btn);
}

// Run this every 2 seconds to handle page changes
setInterval(init, 2000);
