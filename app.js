// Phishing Detection Application

// DOM Elements
const urlInput = document.getElementById('urlInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const loadingState = document.getElementById('loadingState');
const resultsSection = document.getElementById('resultsSection');
const riskBadge = document.getElementById('riskBadge');
const riskScore = document.getElementById('riskScore');
const riskDescription = document.getElementById('riskDescription');
const analyzedUrl = document.getElementById('analyzedUrl');
const indicatorsList = document.getElementById('indicatorsList');
const progressCircle = document.getElementById('progressCircle');

// Phishing Detection Configuration
const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.work', '.date', '.racing', '.review', '.download', '.stream', '.science', '.cricket'];

const SUSPICIOUS_KEYWORDS = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'banking', 'suspended', 'locked', 'unusual', 'click', 'urgent', 'password', 'signin', 'wallet', 'crypto'];

const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly', 'adf.ly', 'short.io'];

const COMMON_BRANDS = {
    'paypal': ['paypa1', 'paypai', 'paypall', 'paypa-', 'paypa_'],
    'google': ['gooogle', 'googie', 'goog1e', 'gogle'],
    'amazon': ['amazom', 'amaz0n', 'arnazon', 'amazon-'],
    'microsoft': ['micros0ft', 'micosoft', 'microsft', 'micro-soft'],
    'facebook': ['faceb00k', 'facebo0k', 'facebok', 'face-book'],
    'apple': ['app1e', 'appl3', 'aple', 'apple-'],
    'netflix': ['netf1ix', 'netfl1x', 'netflex', 'net-flix'],
    'instagram': ['instagr4m', 'insta-gram', 'instaqram'],
    'github': ['githib', 'gith-ub', 'git-hub'],
    'linkedin': ['link3din', 'linked-in', 'linkedln']
};

// Event Listeners
analyzeBtn.addEventListener('click', analyzeURL);
urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        analyzeURL();
    }
});

// Main Analysis Function
async function analyzeURL() {
    const url = urlInput.value.trim();
    
    if (!url) {
        showError('Please enter a URL to analyze');
        return;
    }
    
    if (!isValidURL(url)) {
        showError('Please enter a valid URL (e.g., https://example.com)');
        return;
    }
    
    // Show loading state
    showLoading();
    
    // Simulate analysis delay for better UX
    setTimeout(() => {
        const result = performPhishingAnalysis(url);
        displayResults(result);
    }, 1500);
}

// URL Validation
function isValidURL(string) {
    try {
        // Add protocol if missing
        if (!string.match(/^https?:\/\//i)) {
            string = 'http://' + string;
        }
        const url = new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

// Core Phishing Analysis Logic
function performPhishingAnalysis(inputUrl) {
    // Normalize URL
    if (!inputUrl.match(/^https?:\/\//i)) {
        inputUrl = 'http://' + inputUrl;
    }
    
    const url = new URL(inputUrl);
    const indicators = [];
    let score = 0;
    
    // 1. Check for HTTPS
    if (url.protocol === 'http:') {
        indicators.push({
            type: 'warning',
            title: 'No HTTPS Encryption',
            description: 'The URL uses HTTP instead of HTTPS, which is less secure',
            severity: 15
        });
        score += 15;
    } else {
        indicators.push({
            type: 'safe',
            title: 'HTTPS Detected',
            description: 'The URL uses secure HTTPS protocol',
            severity: 0
        });
    }
    
    // 2. Check for IP Address
    const ipPattern = /^(https?:\/\/)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
    if (ipPattern.test(inputUrl)) {
        indicators.push({
            type: 'danger',
            title: 'IP Address Instead of Domain',
            description: 'Legitimate websites rarely use IP addresses directly',
            severity: 25
        });
        score += 25;
    }
    
    // 3. Check for Suspicious TLDs
    const hostname = url.hostname.toLowerCase();
    const suspiciousTLD = SUSPICIOUS_TLDS.find(tld => hostname.endsWith(tld));
    if (suspiciousTLD) {
        indicators.push({
            type: 'danger',
            title: 'Suspicious Top-Level Domain',
            description: `The TLD "${suspiciousTLD}" is commonly used in phishing attacks`,
            severity: 20
        });
        score += 20;
    }
    
    // 4. Check Subdomain Count
    const subdomains = hostname.split('.');
    if (subdomains.length > 4) {
        indicators.push({
            type: 'warning',
            title: 'Excessive Subdomains',
            description: `Found ${subdomains.length - 2} subdomains, which may indicate obfuscation`,
            severity: 15
        });
        score += 15;
    }
    
    // 5. Check for Look-alike Domains
    for (const [brand, variants] of Object.entries(COMMON_BRANDS)) {
        for (const variant of variants) {
            if (hostname.includes(variant)) {
                indicators.push({
                    type: 'danger',
                    title: 'Look-alike Domain Detected',
                    description: `Domain contains "${variant}" which mimics "${brand}"`,
                    severity: 30
                });
                score += 30;
                break;
            }
        }
    }
    
    // 6. Check for URL Shorteners
    const isShortener = URL_SHORTENERS.some(shortener => hostname.includes(shortener));
    if (isShortener) {
        indicators.push({
            type: 'warning',
            title: 'URL Shortener Detected',
            description: 'Shortened URLs can hide the true destination',
            severity: 15
        });
        score += 15;
    }
    
    // 7. Check for Suspicious Keywords
    const fullUrl = inputUrl.toLowerCase();
    const foundKeywords = SUSPICIOUS_KEYWORDS.filter(keyword => fullUrl.includes(keyword));
    if (foundKeywords.length > 0) {
        indicators.push({
            type: 'warning',
            title: 'Suspicious Keywords Found',
            description: `Contains keywords often used in phishing: ${foundKeywords.slice(0, 3).join(', ')}`,
            severity: 10 * foundKeywords.length
        });
        score += 10 * foundKeywords.length;
    }
    
    // 8. Check for @ Symbol (username in URL)
    if (inputUrl.includes('@')) {
        indicators.push({
            type: 'danger',
            title: 'Suspicious @ Symbol',
            description: 'The @ symbol can be used to hide the actual domain',
            severity: 25
        });
        score += 25;
    }
    
    // 9. Check for Unusual Port Numbers
    if (url.port && !['80', '443', ''].includes(url.port)) {
        indicators.push({
            type: 'warning',
            title: 'Unusual Port Number',
            description: `Non-standard port ${url.port} detected`,
            severity: 10
        });
        score += 10;
    }
    
    // 10. Check URL Length
    if (inputUrl.length > 75) {
        indicators.push({
            type: 'warning',
            title: 'Unusually Long URL',
            description: 'Very long URLs can be used to hide malicious content',
            severity: 10
        });
        score += 10;
    }
    
    // 11. Check for Multiple Hyphens
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount > 2) {
        indicators.push({
            type: 'warning',
            title: 'Excessive Hyphens in Domain',
            description: `Found ${hyphenCount} hyphens, which may indicate typosquatting`,
            severity: 10
        });
        score += 10;
    }
    
    // 12. Check for Unicode/Homograph Characters
    if (/[^\x00-\x7F]/.test(hostname)) {
        indicators.push({
            type: 'danger',
            title: 'Non-ASCII Characters Detected',
            description: 'Unicode characters can be used for homograph attacks',
            severity: 20
        });
        score += 20;
    }
    
    // Cap score at 100
    score = Math.min(score, 100);
    
    // Determine risk level
    let riskLevel, riskText, recommendations;
    if (score <= 10) {
        riskLevel = 'safe';
        riskText = 'Safe';
        recommendations = 'This URL appears to be legitimate with no major red flags detected.';
    } else if (score <= 30) {
        riskLevel = 'low';
        riskText = 'Low Risk';
        recommendations = 'This URL has minor concerns but is likely safe. Exercise normal caution.';
    } else if (score <= 50) {
        riskLevel = 'medium';
        riskText = 'Medium Risk';
        recommendations = 'This URL shows several warning signs. Verify the source before proceeding.';
    } else if (score <= 75) {
        riskLevel = 'high';
        riskText = 'High Risk';
        recommendations = 'This URL has multiple phishing indicators. Avoid entering sensitive information.';
    } else {
        riskLevel = 'critical';
        riskText = 'Critical Risk';
        recommendations = 'This URL is highly suspicious and likely a phishing attempt. Do not proceed.';
    }
    
    // If no issues found, add a positive indicator
    if (indicators.length === 1 && indicators[0].type === 'safe') {
        indicators.push({
            type: 'safe',
            title: 'Domain Appears Legitimate',
            description: 'No major phishing indicators detected',
            severity: 0
        });
        indicators.push({
            type: 'safe',
            title: 'Standard URL Structure',
            description: 'The URL follows normal conventions',
            severity: 0
        });
    }
    
    return {
        url: inputUrl,
        score: score,
        riskLevel: riskLevel,
        riskText: riskText,
        recommendations: recommendations,
        indicators: indicators
    };
}

// Display Results
function displayResults(result) {
    hideLoading();
    resultsSection.classList.remove('hidden');
    
    // Update risk badge
    riskBadge.className = `inline-block px-6 py-3 rounded-full font-bold text-lg mb-6 risk-${result.riskLevel}`;
    riskBadge.textContent = result.riskText;
    
    // Animate score
    animateScore(result.score);
    
    // Update progress circle
    const circumference = 2 * Math.PI * 88;
    const offset = circumference - (result.score / 100) * circumference;
    progressCircle.style.strokeDashoffset = offset;
    
    // Update gradient based on risk
    const gradient = document.querySelector('#gradient');
    if (result.score > 75) {
        gradient.innerHTML = '<stop offset="0%" style="stop-color:#dc2626;stop-opacity:1" /><stop offset="100%" style="stop-color:#991b1b;stop-opacity:1" />';
    } else if (result.score > 50) {
        gradient.innerHTML = '<stop offset="0%" style="stop-color:#ef4444;stop-opacity:1" /><stop offset="100%" style="stop-color:#dc2626;stop-opacity:1" />';
    } else if (result.score > 30) {
        gradient.innerHTML = '<stop offset="0%" style="stop-color:#f59e0b;stop-opacity:1" /><stop offset="100%" style="stop-color:#d97706;stop-opacity:1" />';
    } else if (result.score > 10) {
        gradient.innerHTML = '<stop offset="0%" style="stop-color:#84cc16;stop-opacity:1" /><stop offset="100%" style="stop-color:#65a30d;stop-opacity:1" />';
    } else {
        gradient.innerHTML = '<stop offset="0%" style="stop-color:#10b981;stop-opacity:1" /><stop offset="100%" style="stop-color:#059669;stop-opacity:1" />';
    }
    
    // Update analyzed URL and description
    analyzedUrl.textContent = result.url;
    riskDescription.textContent = result.recommendations;
    
    // Display indicators
    indicatorsList.innerHTML = '';
    result.indicators.forEach((indicator, index) => {
        const indicatorEl = document.createElement('div');
        indicatorEl.className = `indicator-item indicator-${indicator.type}`;
        indicatorEl.style.animationDelay = `${index * 0.1}s`;
        indicatorEl.innerHTML = `
            <div class="flex items-start gap-3">
                <div class="flex-shrink-0 mt-1">
                    ${getIndicatorIcon(indicator.type)}
                </div>
                <div class="flex-1">
                    <h4 class="font-semibold text-white mb-1">${indicator.title}</h4>
                    <p class="text-sm text-gray-300">${indicator.description}</p>
                </div>
            </div>
        `;
        indicatorsList.appendChild(indicatorEl);
    });
    
    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Animate Score Counter
function animateScore(targetScore) {
    let currentScore = 0;
    const duration = 1500;
    const increment = targetScore / (duration / 16);
    
    const timer = setInterval(() => {
        currentScore += increment;
        if (currentScore >= targetScore) {
            currentScore = targetScore;
            clearInterval(timer);
        }
        riskScore.textContent = Math.round(currentScore);
    }, 16);
}

// Get Indicator Icon
function getIndicatorIcon(type) {
    if (type === 'safe') {
        return `
            <svg class="w-6 h-6 text-green-400" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
            </svg>
        `;
    } else if (type === 'warning') {
        return `
            <svg class="w-6 h-6 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
            </svg>
        `;
    } else {
        return `
            <svg class="w-6 h-6 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>
            </svg>
        `;
    }
}

// UI Helper Functions
function showLoading() {
    loadingState.classList.remove('hidden');
    resultsSection.classList.add('hidden');
    analyzeBtn.disabled = true;
    analyzeBtn.classList.add('opacity-50', 'cursor-not-allowed');
}

function hideLoading() {
    loadingState.classList.add('hidden');
    analyzeBtn.disabled = false;
    analyzeBtn.classList.remove('opacity-50', 'cursor-not-allowed');
}

function showError(message) {
    // Simple alert for errors (could be enhanced with a custom modal)
    const errorDiv = document.createElement('div');
    errorDiv.className = 'fixed top-4 right-4 bg-red-500 text-white px-6 py-4 rounded-lg shadow-lg z-50 animate-fade-in';
    errorDiv.innerHTML = `
        <div class="flex items-center gap-3">
            <svg class="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>
            </svg>
            <span>${message}</span>
        </div>
    `;
    document.body.appendChild(errorDiv);
    
    setTimeout(() => {
        errorDiv.remove();
    }, 3000);
}
