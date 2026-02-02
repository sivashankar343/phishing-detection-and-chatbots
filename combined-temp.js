// Character sets for password generation
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const NUMBERS = '0123456789';
const SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?~';

// DOM Elements
const lengthSlider = document.getElementById('passwordLength');
const lengthValue = document.getElementById('lengthValue');
const generateBtn = document.getElementById('generateBtn');
const passwordDisplay = document.getElementById('passwordDisplay');
const generatedPassword = document.getElementById('generatedPassword');
const copyBtn = document.getElementById('copyBtn');
const downloadBtn = document.getElementById('downloadBtn');
const regenerateBtn = document.getElementById('regenerateBtn');
const strengthBadge = document.getElementById('strengthBadge');
const strengthMeter = document.getElementById('strengthMeter');
const strengthText = document.getElementById('strengthText');

// User data inputs
const userNameInput = document.getElementById('userName');
const platformSelect = document.getElementById('platformSelect');
const userBirthdayInput = document.getElementById('userBirthday');
const userPhoneInput = document.getElementById('userPhone');

// Checkboxes
const includeUppercase = document.getElementById('includeUppercase');
const includeLowercase = document.getElementById('includeLowercase');
const includeNumbers = document.getElementById('includeNumbers');
const includeSymbols = document.getElementById('includeSymbols');

// Update length value display
lengthSlider.addEventListener('input', (e) => {
    lengthValue.textContent = e.target.value;
});

// Generate password with AI-powered randomness
function generateSecurePassword(length, options) {
    let charset = '';
    let password = '';

    // Build character set based on options
    if (options.uppercase) charset += UPPERCASE;
    if (options.lowercase) charset += LOWERCASE;
    if (options.numbers) charset += NUMBERS;
    if (options.symbols) charset += SYMBOLS;

    if (charset === '') {
        alert('Please select at least one character type!');
        return null;
    }

    // Use crypto.getRandomValues for cryptographically strong random numbers
    const randomValues = new Uint32Array(length);
    window.crypto.getRandomValues(randomValues);

    // Ensure at least one character from each selected type
    const guaranteedChars = [];
    if (options.uppercase) guaranteedChars.push(UPPERCASE[Math.floor(Math.random() * UPPERCASE.length)]);
    if (options.lowercase) guaranteedChars.push(LOWERCASE[Math.floor(Math.random() * LOWERCASE.length)]);
    if (options.numbers) guaranteedChars.push(NUMBERS[Math.floor(Math.random() * NUMBERS.length)]);
    if (options.symbols) guaranteedChars.push(SYMBOLS[Math.floor(Math.random() * SYMBOLS.length)]);

    // Generate remaining characters
    for (let i = 0; i < length - guaranteedChars.length; i++) {
        const randomIndex = randomValues[i] % charset.length;
        password += charset[randomIndex];
    }

    // Insert guaranteed characters at random positions
    guaranteedChars.forEach(char => {
        const randomPosition = Math.floor(Math.random() * password.length);
        password = password.slice(0, randomPosition) + char + password.slice(randomPosition);
    });

    // Trim to exact length if needed
    password = password.slice(0, length);

    // Shuffle the password one more time for extra randomness
    password = shuffleString(password);

    return password;
}

// Shuffle string using Fisher-Yates algorithm
function shuffleString(str) {
    const arr = str.split('');
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr.join('');
}

// Validate that password is not related to user data
function validatePasswordSecurity(password, userData) {
    const warnings = [];

    // Convert password to lowercase for comparison
    const passLower = password.toLowerCase();

    // Check against name
    if (userData.name) {
        const nameParts = userData.name.toLowerCase().split(' ');
        nameParts.forEach(part => {
            if (part.length > 2 && passLower.includes(part)) {
                warnings.push(`Password contains part of your name: "${part}"`);
            }
        });
    }

    // Check against birthday
    if (userData.birthday) {
        const birthParts = userData.birthday.split('-'); // YYYY-MM-DD
        birthParts.forEach(part => {
            if (password.includes(part)) {
                warnings.push('Password contains your birth date');
            }
        });
    }

    // Check against phone
    if (userData.phone) {
        const phoneDigits = userData.phone.replace(/\D/g, '');
        if (phoneDigits.length > 3) {
            const phoneSegments = [
                phoneDigits.slice(0, 3),
                phoneDigits.slice(-4),
                phoneDigits.slice(3, 6)
            ];
            phoneSegments.forEach(segment => {
                if (password.includes(segment)) {
                    warnings.push('Password contains part of your phone number');
                }
            });
        }
    }

    return warnings;
}

// Calculate password strength
function calculateStrength(password) {
    let score = 0;

    // Length score
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;
    if (password.length >= 20) score += 1;

    // Character variety
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 2;

    // No repeated characters
    if (!/(.)\1{2,}/.test(password)) score += 1;

    // Map score to strength level
    if (score <= 3) return { level: 'weak', text: 'Weak', color: 'weak' };
    if (score <= 6) return { level: 'medium', text: 'Medium', color: 'medium' };
    if (score <= 9) return { level: 'strong', text: 'Strong', color: 'strong' };
    return { level: 'very-strong', text: 'Very Strong', color: 'very-strong' };
}

// Update strength display
function updateStrengthDisplay(strength) {
    // Update badge
    strengthBadge.className = `strength-badge strength-${strength.color}`;
    strengthBadge.textContent = strength.text;

    // Update meter
    strengthMeter.className = `strength-fill ${strength.level}`;

    // Update text
    strengthText.className = `text-sm font-bold`;
    strengthText.textContent = strength.text;

    // Color text based on strength
    if (strength.level === 'weak') strengthText.style.color = '#ef4444';
    else if (strength.level === 'medium') strengthText.style.color = '#fb923c';
    else if (strength.level === 'strong') strengthText.style.color = '#22c55e';
    else strengthText.style.color = '#06b6d4';
}

// Get user data
function getUserData() {
    return {
        name: userNameInput.value.trim(),
        platform: platformSelect.value,
        birthday: userBirthdayInput.value,
        phone: userPhoneInput.value.trim()
    };
}

// Main generate function
function handleGenerate() {
    const length = parseInt(lengthSlider.value);
    const options = {
        uppercase: includeUppercase.checked,
        lowercase: includeLowercase.checked,
        numbers: includeNumbers.checked,
        symbols: includeSymbols.checked
    };

    // Generate password
    let password = generateSecurePassword(length, options);

    if (!password) return;

    // Get user data
    const userData = getUserData();

    // Validate security - regenerate if password relates to user data
    let attempts = 0;
    const maxAttempts = 10;
    let warnings = validatePasswordSecurity(password, userData);

    while (warnings.length > 0 && attempts < maxAttempts) {
        password = generateSecurePassword(length, options);
        warnings = validatePasswordSecurity(password, userData);
        attempts++;
    }

    if (warnings.length > 0) {
        console.warn('Generated password after max attempts:', warnings);
    }

    // Display password
    generatedPassword.textContent = password;
    passwordDisplay.classList.remove('hidden');
    passwordDisplay.classList.add('fade-in');

    // Calculate and display strength
    const strength = calculateStrength(password);
    updateStrengthDisplay(strength);

    // Store password for later use
    window.currentPassword = password;
}

// Copy to clipboard
async function copyToClipboard() {
    const password = generatedPassword.textContent;

    try {
        await navigator.clipboard.writeText(password);

        // Visual feedback
        const originalHTML = copyBtn.innerHTML;
        copyBtn.innerHTML = `
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
            </svg>
        `;
        copyBtn.style.color = '#22c55e';

        setTimeout(() => {
            copyBtn.innerHTML = originalHTML;
            copyBtn.style.color = '';
        }, 2000);
    } catch (err) {
        alert('Failed to copy password. Please copy manually.');
        console.error('Copy failed:', err);
    }
}

// Store the file handle globally
let fileHandle = null;

// Download/Save ALL passwords to ONE file - DIRECT SAVE TO USER'S LOCATION
async function downloadPassword() {
    const password = generatedPassword.textContent;
    const userData = getUserData();
    const now = new Date();
    const timestamp = now.toLocaleString('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
    });

    // Platform names mapping
    const platformNames = {
        instagram: 'Instagram',
        whatsapp: 'WhatsApp',
        email: 'Email',
        facebook: 'Facebook',
        twitter: 'X (Twitter)',
        linkedin: 'LinkedIn',
        tiktok: 'TikTok',
        snapchat: 'Snapchat',
        discord: 'Discord',
        telegram: 'Telegram',
        reddit: 'Reddit',
        netflix: 'Netflix',
        spotify: 'Spotify',
        amazon: 'Amazon',
        paypal: 'PayPal',
        banking: 'Banking',
        gaming: 'Gaming',
        work: 'Work Account',
        other: 'Other'
    };

    // Get existing password history from localStorage
    let passwordHistory = localStorage.getItem('passwordHistory') || '';

    // If this is the first entry, add simple header
    if (!passwordHistory) {
        passwordHistory = `GENERATED PASSWORDS\n`;
        passwordHistory += `===================\n\n`;
    }

    // Add new password entry in SIMPLE CLEAN format
    passwordHistory += `[${timestamp}]\n`;

    if (userData.platform) {
        const platformName = platformNames[userData.platform] || userData.platform;
        passwordHistory += `Platform: ${platformName}\n`;
    } else {
        passwordHistory += `Platform: Not specified\n`;
    }

    if (userData.name) {
        passwordHistory += `User: ${userData.name}\n`;
    }

    passwordHistory += `Password: ${password}\n\n`;

    // Save updated history to localStorage
    localStorage.setItem('passwordHistory', passwordHistory);

    // Try to use File System Access API for direct file save
    try {
        // Check if the API is supported
        if ('showSaveFilePicker' in window) {
            // If we don't have a file handle yet, ask user to pick/create a file
            if (!fileHandle) {
                fileHandle = await window.showSaveFilePicker({
                    suggestedName: 'password-history.txt',
                    types: [{
                        description: 'Text Files',
                        accept: { 'text/plain': ['.txt'] }
                    }]
                });
            }

            // Create a writable stream
            const writable = await fileHandle.createWritable();

            // Write the content
            await writable.write(passwordHistory);

            // Close the file
            await writable.close();

            // Visual feedback - SUCCESS
            const originalText = downloadBtn.innerHTML;
            downloadBtn.innerHTML = `
                <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                </svg>
                Saved to File!
            `;

            setTimeout(() => {
                downloadBtn.innerHTML = originalText;
            }, 2000);

        } else {
            // Fallback: Use regular download for browsers that don't support File System Access API
            const blob = new Blob([passwordHistory], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `password-history.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            // Visual feedback - DOWNLOADED
            const originalText = downloadBtn.innerHTML;
            downloadBtn.innerHTML = `
                <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                </svg>
                Downloaded!
            `;

            setTimeout(() => {
                downloadBtn.innerHTML = originalText;
            }, 2000);
        }

    } catch (err) {
        // User cancelled file picker or error occurred
        if (err.name !== 'AbortError') {
            console.error('Error saving file:', err);
            alert('Failed to save file. Please try again.');
        }
    }
}

// Event Listeners
generateBtn.addEventListener('click', handleGenerate);
regenerateBtn.addEventListener('click', handleGenerate);
copyBtn.addEventListener('click', copyToClipboard);
downloadBtn.addEventListener('click', downloadPassword);

// Allow Enter key to generate
document.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !passwordDisplay.classList.contains('hidden')) {
        handleGenerate();
    }
});

// Initialize
console.log('AI Password Generator initialized successfully!');
console.log('All processing happens locally - your data never leaves your browser.');
console.log('Passwords save directly to YOUR chosen file location!');
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
