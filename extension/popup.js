let scoreHistory = [];
let chart = null;

function updateStats() {
    chrome.storage.local.get(['scanned', 'blocked', 'scoreHistory', 'theme'], (res) => {
        document.getElementById('count-scanned').innerText = res.scanned || 0;
        document.getElementById('count-threats').innerText = res.blocked || 0;
        
        // Update score history
        scoreHistory = res.scoreHistory || [];
        updateAverageScore();
        updateChart();
        
        if (res.theme) document.body.setAttribute('data-theme', res.theme);
    });
}

function forceRefresh() {
    updateStats();
    // Also check backend status again
    fetch('http://127.0.0.1:5001/test', { 
        method: 'GET'
    }).then(response => response.json()).then(() => {
        const status = document.getElementById('status-text');
        status.innerHTML = '<span class="icon">✅</span>Shield Active';
        status.style.color = 'var(--success)';
    }).catch(() => {
        const status = document.getElementById('status-text');
        status.innerHTML = '<span class="icon">❌</span>Backend Offline';
        status.style.color = 'var(--danger)';
    });
}

function updateAverageScore() {
    if (scoreHistory.length === 0) {
        document.getElementById('avg-score').innerText = '0';
        document.getElementById('score-fill').style.width = '0%';
        document.getElementById('score-label').innerText = 'No Scans Yet';
        return;
    }
    
    const avgScore = Math.round(scoreHistory.reduce((a, b) => a + b, 0) / scoreHistory.length);
    document.getElementById('avg-score').innerText = avgScore;
    
    const scoreFill = document.getElementById('score-fill');
    const scoreLabel = document.getElementById('score-label');
    
    scoreFill.style.width = avgScore + '%';
    
    if (avgScore < 30) {
        scoreFill.style.background = 'var(--success)';
        scoreLabel.innerText = 'Safe';
    } else if (avgScore < 70) {
        scoreFill.style.background = 'var(--warning)';
        scoreLabel.innerText = 'Caution';
    } else {
        scoreFill.style.background = 'var(--danger)';
        scoreLabel.innerText = 'High Risk';
    }
}

function updateChart() {
    const canvas = document.getElementById('scoreChart');
    const ctx = canvas.getContext('2d');
    
    // Set canvas size
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    
    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    if (scoreHistory.length === 0) {
        ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--text');
        ctx.font = '12px Segoe UI';
        ctx.textAlign = 'center';
        ctx.fillText('No scan data yet', canvas.width / 2, canvas.height / 2);
        return;
    }
    
    // Get last 10 scores
    const recentScores = scoreHistory.slice(-10);
    const padding = 30;
    const chartWidth = canvas.width - (padding * 2);
    const chartHeight = canvas.height - (padding * 2);
    const maxScore = 100;
    
    // Get theme colors
    const textColor = getComputedStyle(document.body).getPropertyValue('--text');
    const primaryColor = getComputedStyle(document.body).getPropertyValue('--primary');
    const gridColor = textColor + '20';
    
    // Draw grid
    ctx.strokeStyle = gridColor;
    ctx.lineWidth = 1;
    ctx.setLineDash([5, 5]);
    
    // Horizontal grid lines
    for (let i = 0; i <= 4; i++) {
        const y = padding + (chartHeight / 4) * i;
        ctx.beginPath();
        ctx.moveTo(padding, y);
        ctx.lineTo(canvas.width - padding, y);
        ctx.stroke();
        
        // Y-axis labels
        ctx.fillStyle = textColor;
        ctx.font = '10px Segoe UI';
        ctx.textAlign = 'right';
        ctx.fillText((100 - i * 25).toString(), padding - 5, y + 3);
    }
    
    // Draw axes
    ctx.setLineDash([]);
    ctx.strokeStyle = textColor;
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(padding, padding);
    ctx.lineTo(padding, canvas.height - padding);
    ctx.lineTo(canvas.width - padding, canvas.height - padding);
    ctx.stroke();
    
    // Draw data line and points
    if (recentScores.length > 0) {
        // Draw line
        ctx.strokeStyle = primaryColor;
        ctx.lineWidth = 3;
        ctx.beginPath();
        
        recentScores.forEach((score, index) => {
            const x = padding + (index / (recentScores.length - 1 || 1)) * chartWidth;
            const y = canvas.height - padding - (score / maxScore) * chartHeight;
            
            if (index === 0) {
                ctx.moveTo(x, y);
            } else {
                ctx.lineTo(x, y);
            }
        });
        
        ctx.stroke();
        
        // Draw points and values
        recentScores.forEach((score, index) => {
            const x = padding + (index / (recentScores.length - 1 || 1)) * chartWidth;
            const y = canvas.height - padding - (score / maxScore) * chartHeight;
            
            // Draw point
            ctx.fillStyle = primaryColor;
            ctx.beginPath();
            ctx.arc(x, y, 5, 0, 2 * Math.PI);
            ctx.fill();
            
            // Draw value
            ctx.fillStyle = textColor;
            ctx.font = 'bold 10px Segoe UI';
            ctx.textAlign = 'center';
            ctx.fillText(score.toString(), x, y - 10);
        });
    }
    
    // Draw X-axis label
    ctx.fillStyle = textColor;
    ctx.font = '10px Segoe UI';
    ctx.textAlign = 'center';
    ctx.fillText('Recent Scans', canvas.width / 2, canvas.height - 5);
}

// Initial Load
document.addEventListener('DOMContentLoaded', () => {
    console.log('Popup loaded, updating stats...');
    updateStats();
});

// Also update immediately for popup opens
updateStats();

// Theme Toggle
document.getElementById('theme-toggle').onclick = () => {
    const isDark = document.body.getAttribute('data-theme') === 'dark';
    const newTheme = isDark ? 'light' : 'dark';
    document.body.setAttribute('data-theme', newTheme);
    chrome.storage.local.set({theme: newTheme});
};

// Refresh button
document.getElementById('refresh-btn').onclick = () => {
    forceRefresh();
};

// Check if Backend is alive
fetch('http://127.0.0.1:5001/test', { 
    method: 'GET'
}).then(response => response.json()).then(() => {
    const status = document.getElementById('status-text');
    status.innerHTML = '<span class="icon">✅</span>Shield Active';
    status.style.color = 'var(--success)';
}).catch(() => {
    const status = document.getElementById('status-text');
    status.innerHTML = '<span class="icon">❌</span>Backend Offline';
    status.style.color = 'var(--danger)';
});

// Listen for scan results to update score history
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SCAN_RESULT' && message.score !== undefined) {
        // Add score to history
        chrome.storage.local.get(['scoreHistory'], (res) => {
            let history = res.scoreHistory || [];
            history.push(message.score);
            // Keep only last 50 scores
            if (history.length > 50) {
                history = history.slice(-50);
            }
            chrome.storage.local.set({ scoreHistory: history }, () => {
                // Update stats immediately after adding score
                updateStats();
            });
        });
    }
});

// Refresh stats whenever we open the popup
chrome.storage.onChanged.addListener(updateStats);
