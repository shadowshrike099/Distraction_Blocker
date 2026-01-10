// options.js - Local state management for Cognitive Defense options/dashboard UI

// Storage keys for options
const OPTIONS_STORAGE_KEYS = {
    BLOCKED_SITES: 'optionsBlockedSites',
    FOCUS_DURATION: 'optionsFocusDuration',
    STRICT_MODE: 'optionsStrictMode',
    EMERGENCY_CODE: 'optionsEmergencyCode',
    MAX_ATTEMPTS: 'optionsMaxAttempts'
};

// Local state variables
let blockedSites = [];
let focusDuration = 25; // minutes
let strictModeEnabled = false;
let emergencyRules = { code: '', maxAttempts: 3 };
let guardianLimits = { global: 10, overrides: {} };
let dailyUsage = {};

// DOM elements
const tabBtns = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');
const container = document.querySelector('.container');
// Session Lock Overlay
const lockOverlay = document.createElement('div');
lockOverlay.id = 'session-lock-overlay';
lockOverlay.innerHTML = `
    <div class="lock-message">
        <h2>Session Active</h2>
        <p>Dashboard is locked while a focus session is in progress.</p>
        <p>Use the extension popup to manage your session.</p>
    </div>
`;
lockOverlay.style.display = 'none';
document.body.appendChild(lockOverlay);
const blocklistForm = document.getElementById('blocklist-form');
const siteInput = document.getElementById('site-input');
const blocklist = document.getElementById('blocklist');
const durationForm = document.getElementById('duration-form');
const durationInput = document.getElementById('duration-input');
const currentDuration = document.getElementById('current-duration');
const strictToggle = document.getElementById('strict-toggle');
const strictStatus = document.getElementById('strict-status');
const emergencyForm = document.getElementById('emergency-form');
const unlockCodeInput = document.getElementById('unlock-code');
const maxAttemptsInput = document.getElementById('max-attempts');
const emergencyStatus = document.getElementById('emergency-status');
const logsContainer = document.getElementById('logs-container');
const refreshLogsBtn = document.getElementById('refresh-logs');
const saveAllBtn = document.getElementById('save-all');
const resetBtn = document.getElementById('reset');
const riskScoreEl = document.getElementById('risk-score');
const scoreCircle = document.getElementById('score-circle');
const riskDescription = document.getElementById('risk-description');
const refreshRiskBtn = document.getElementById('refresh-risk');
const globalLimitInput = document.getElementById('global-limit');
const saveGuardianLimitBtn = document.getElementById('save-guardian-limit');
const guardianUsageBody = document.getElementById('guardian-usage-body');

// Initialize UI
async function init() {
    await loadSettings();
    setupEventListeners();
    renderBlocklist();
    renderLogs();
    renderRiskScore();
    renderGuardianSettings();
    updateUI();
    checkSessionStatus();
}

async function checkSessionStatus() {
    const { sessionEndTime } = await chrome.storage.local.get('sessionEndTime');
    if (sessionEndTime && Date.now() < sessionEndTime) {
        document.body.classList.add('session-locked');
        lockOverlay.style.display = 'flex';
        // Disable all inputs
        document.querySelectorAll('input, button').forEach(el => {
            if (el.id !== 'refresh-logs' && el.id !== 'refresh-risk') el.disabled = true;
        });
    } else {
        document.body.classList.remove('session-locked');
        lockOverlay.style.display = 'none';
        document.querySelectorAll('input, button').forEach(el => el.disabled = false);
        updateUI(); // Re-run updateUI to restore correct enabled states
    }
}

// Listen for session start/end
chrome.storage.onChanged.addListener((changes) => {
    if (changes.sessionEndTime) {
        checkSessionStatus();
    }
});

// Tab navigation
function switchTab(targetTab) {
    tabBtns.forEach(btn => btn.classList.remove('active'));
    tabContents.forEach(content => content.classList.remove('active'));

    const activeBtn = document.querySelector(`[data-tab="${targetTab}"]`);
    const activeContent = document.getElementById(`${targetTab}-tab`);

    if (activeBtn && activeContent) {
        activeBtn.classList.add('active');
        activeContent.classList.add('active');
    }
}

// Blocklist management
function addSite(e) {
    e.preventDefault();
    const url = siteInput.value.trim();
    if (url) {
        const normalizedUrl = normalizeUrlToPattern(url);
        if (normalizedUrl && !blockedSites.includes(normalizedUrl)) {
            blockedSites.push(normalizedUrl);
            renderBlocklist();
            siteInput.value = '';
            saveSetting(OPTIONS_STORAGE_KEYS.BLOCKED_SITES, blockedSites);
        }
    }
}

function removeSite(url) {
    blockedSites = blockedSites.filter(site => site !== url);
    renderBlocklist();
    saveSetting(OPTIONS_STORAGE_KEYS.BLOCKED_SITES, blockedSites);
}

function normalizeUrlToPattern(url) {
    try {
        // Ensure protocol
        if (!url.startsWith('http')) {
            url = 'https://' + url;
        }
        const urlObj = new URL(url);
        let domain = urlObj.hostname;

        // Strip www. prefix for consistent storage
        if (domain.startsWith('www.')) {
            domain = domain.substring(4);
        }

        return domain; // Store just 'example.com'
    } catch (e) {
        alert('Invalid URL');
        return null;
    }
}

function renderBlocklist() {
    blocklist.innerHTML = '';
    blockedSites.forEach(site => {
        const li = document.createElement('li');
        li.innerHTML = `
            <span>${site}</span>
            <button class="remove-btn" data-url="${site}">Remove</button>
        `;
        blocklist.appendChild(li);
    });
}

// Duration management
function setDuration(e) {
    e.preventDefault();
    const duration = parseInt(durationInput.value);
    if (duration >= 1 && duration <= 480) {
        focusDuration = duration;
        updateUI();
        saveSetting(OPTIONS_STORAGE_KEYS.FOCUS_DURATION, duration);
    }
}

// Strict mode toggle
function toggleStrictMode() {
    strictModeEnabled = strictToggle.checked;
    updateUI();
    saveSetting(OPTIONS_STORAGE_KEYS.STRICT_MODE, strictModeEnabled);
}

// Emergency rules
async function saveEmergencyRules(e) {
    e.preventDefault();
    if (unlockCodeInput.value) {
        const { hash, salt } = await hashPassword(unlockCodeInput.value);
        emergencyRules.code = hash;
        saveSetting('optionsEmergencyCodeSalt', salt);
    } else {
        emergencyRules.code = ''; // Allow clearing
        saveSetting('optionsEmergencyCodeSalt', null);
    }
    emergencyRules.maxAttempts = parseInt(maxAttemptsInput.value);
    updateUI();
    saveSetting(OPTIONS_STORAGE_KEYS.EMERGENCY_CODE, emergencyRules.code);
    saveSetting(OPTIONS_STORAGE_KEYS.MAX_ATTEMPTS, emergencyRules.maxAttempts);
}

// Hash password/code
// Hash password using PBKDF2 (Matches background.js)
async function hashPassword(password, salt = null) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);

    // Generate or use provided salt
    let saltBuffer;
    if (salt) {
        const match = salt.match(/.{1,2}/g);
        const saltBytes = new Uint8Array(match ? match.map(byte => parseInt(byte, 16)) : []);
        saltBuffer = saltBytes.buffer;
    } else {
        saltBuffer = crypto.getRandomValues(new Uint8Array(16));
    }

    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        data,
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
    );

    const checkSalt = salt ? saltBuffer : saltBuffer;

    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: checkSalt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        256
    );

    const hashArray = Array.from(new Uint8Array(derivedBits));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    const saltArray = Array.from(new Uint8Array(checkSalt));
    const saltHex = saltArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return { hash: hashHex, salt: saltHex };
}

// Logs
function renderLogs() {
    // Fetch logs from background
    chrome.runtime.sendMessage({ type: 'GET_LOGS' }, (response) => {
        if (response.success) {
            logsContainer.innerHTML = '';
            response.logs.forEach(log => {
                const div = document.createElement('div');
                div.className = `log-entry ${log.type}`;
                div.textContent = `[${new Date(log.timestamp).toLocaleString()}] ${log.type.toUpperCase()}: ${log.event.replace(/_/g, ' ')}`;
                if (Object.keys(log.details).length > 0) {
                    div.textContent += ` (${JSON.stringify(log.details)})`;
                }
                logsContainer.appendChild(div);
            });
        } else {
            logsContainer.innerHTML = '<div class="log-entry error">Failed to load logs</div>';
        }
    });
}

function refreshLogs() {
    renderLogs();
}

// Risk score
function renderRiskScore() {
    chrome.runtime.sendMessage({ type: 'GET_RISK_SCORE' }, (response) => {
        if (response.success) {
            const score = response.score;
            scoreCircle.textContent = score;
            scoreCircle.style.background = `conic-gradient(#007acc 0% ${score}%, #e0e0e0 ${score}% 100%)`;

            let riskLevel = 'low-risk';
            let description = 'Low risk - Good focus habits';
            if (score >= 70) {
                riskLevel = 'high-risk';
                description = 'High risk - Consider adjusting habits';
            } else if (score >= 40) {
                riskLevel = 'medium-risk';
                description = 'Medium risk - Monitor behavior';
            }

            scoreCircle.className = `score-circle ${riskLevel}`;
            riskDescription.textContent = description;
        } else {
            riskDescription.textContent = 'Failed to calculate risk score';
        }
    });
}

function refreshRiskScore() {
    renderRiskScore();
}

// UI updates
function updateUI() {
    currentDuration.textContent = `Current: ${focusDuration} minutes`;
    strictStatus.textContent = strictModeEnabled ? 'Enabled' : 'Disabled';
    strictStatus.className = `status-indicator ${strictModeEnabled ? 'enabled' : 'disabled'}`;
    emergencyStatus.textContent = emergencyRules.code ? 'Rules configured (Hashed)' : 'No rules set';
}

// Settings persistence
async function loadSettings() {
    try {
        const result = await chrome.storage.local.get([
            OPTIONS_STORAGE_KEYS.BLOCKED_SITES,
            OPTIONS_STORAGE_KEYS.FOCUS_DURATION,
            OPTIONS_STORAGE_KEYS.STRICT_MODE,
            OPTIONS_STORAGE_KEYS.EMERGENCY_CODE,
            OPTIONS_STORAGE_KEYS.MAX_ATTEMPTS
        ]);
        blockedSites = result[OPTIONS_STORAGE_KEYS.BLOCKED_SITES] || [];
        focusDuration = result[OPTIONS_STORAGE_KEYS.FOCUS_DURATION] || 25;
        strictModeEnabled = result[OPTIONS_STORAGE_KEYS.STRICT_MODE] || false;
        emergencyRules.code = result[OPTIONS_STORAGE_KEYS.EMERGENCY_CODE] || '';
        emergencyRules.code = result[OPTIONS_STORAGE_KEYS.EMERGENCY_CODE] || '';
        emergencyRules.maxAttempts = result[OPTIONS_STORAGE_KEYS.MAX_ATTEMPTS] || 3;

        // Guardian
        const guardianResult = await chrome.storage.local.get(['timeGuardianLimits', 'dailyUsage']);
        guardianLimits = guardianResult.timeGuardianLimits || { global: 10, overrides: {} };
        dailyUsage = guardianResult.dailyUsage || {};
    } catch (error) {
        console.warn('Failed to load settings:', error);
    }
}

async function saveSetting(key, value) {
    try {
        await chrome.storage.local.set({ [key]: value });
    } catch (error) {
        console.warn('Failed to save setting:', error);
    }
}

async function saveAllSettings() {
    try {
        await chrome.storage.local.set({
            [OPTIONS_STORAGE_KEYS.BLOCKED_SITES]: blockedSites,
            [OPTIONS_STORAGE_KEYS.FOCUS_DURATION]: focusDuration,
            [OPTIONS_STORAGE_KEYS.STRICT_MODE]: strictModeEnabled,
            [OPTIONS_STORAGE_KEYS.EMERGENCY_CODE]: emergencyRules.code,
            [OPTIONS_STORAGE_KEYS.MAX_ATTEMPTS]: emergencyRules.maxAttempts
        });
        alert('Settings saved successfully!');
    } catch (error) {
        alert('Failed to save settings: ' + error.message);
    }
}

async function resetSettings() {
    if (confirm('Reset all settings to defaults?')) {
        blockedSites = [];
        focusDuration = 25;
        strictModeEnabled = false;
        emergencyRules = { code: '', maxAttempts: 3 };
        renderBlocklist();
        updateUI();
        renderLogs();
        renderRiskScore();
        try {
            await chrome.storage.local.remove([
                OPTIONS_STORAGE_KEYS.BLOCKED_SITES,
                OPTIONS_STORAGE_KEYS.FOCUS_DURATION,
                OPTIONS_STORAGE_KEYS.STRICT_MODE,
                OPTIONS_STORAGE_KEYS.EMERGENCY_CODE,
                OPTIONS_STORAGE_KEYS.MAX_ATTEMPTS
            ]);
        } catch (error) {
            console.warn('Failed to clear storage:', error);
        }
    }
}

// Event listeners
function setupEventListeners() {
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });

    blocklistForm.addEventListener('submit', addSite);
    blocklist.addEventListener('click', (e) => {
        if (e.target.classList.contains('remove-btn')) {
            removeSite(e.target.dataset.url);
        }
    });

    durationForm.addEventListener('submit', setDuration);
    strictToggle.addEventListener('change', toggleStrictMode);
    emergencyForm.addEventListener('submit', saveEmergencyRules);
    refreshLogsBtn.addEventListener('click', refreshLogs);
    saveAllBtn.addEventListener('click', saveAllSettings);
    resetBtn.addEventListener('click', resetSettings);
    resetBtn.addEventListener('click', resetSettings);
    refreshRiskBtn.addEventListener('click', refreshRiskScore);
    saveGuardianLimitBtn.addEventListener('click', saveGuardianLimit);
}

// Guardian Functions
function renderGuardianSettings() {
    globalLimitInput.value = Math.floor(guardianLimits.global / 60); // Convert seconds to minutes for display
    renderGuardianUsage();
}

function saveGuardianLimit() {
    const mins = parseInt(globalLimitInput.value);
    if (mins > 0) {
        guardianLimits.global = mins * 60; // Store as seconds
        saveGuardianSettings();
        alert('Daily limit updated');
    }
}

function saveGuardianSettings() {
    chrome.storage.local.set({ timeGuardianLimits: guardianLimits });
    renderGuardianSettings();
}

function renderGuardianUsage() {
    guardianUsageBody.innerHTML = '';
    const SITES = ['facebook.com', 'instagram.com', 'tiktok.com', 'youtube.com', 'x.com', 'twitter.com', 'reddit.com', 'netflix.com'];

    // Merge known sites with any other usage data
    const allDomains = new Set([...SITES, ...Object.keys(dailyUsage)]);

    allDomains.forEach(domain => {
        const usageSec = dailyUsage[domain] || 0;
        const usageMins = Math.floor(usageSec / 60);

        // Determine limit
        const limitSec = guardianLimits.overrides[domain] !== undefined ? guardianLimits.overrides[domain] : guardianLimits.global;
        const limitMins = Math.floor(limitSec / 60);

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="padding: 10px;">${domain}</td>
            <td style="padding: 10px; font-weight: bold;">${usageMins}m</td>
            <td style="padding: 10px;">${limitMins}m</td>
        `;
        guardianUsageBody.appendChild(tr);
    });
}

// Initialize on load
document.addEventListener('DOMContentLoaded', init);