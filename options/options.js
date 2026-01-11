// options.js - Local state management for Cognitive Defense options/dashboard UI
// STORAGE_KEYS and DISTRACTING_SITES are loaded from config.js

// Storage keys for options (using centralized STORAGE_KEYS)
const OPTIONS_STORAGE_KEYS = {
    BLOCKED_SITES: STORAGE_KEYS.OPTIONS_BLOCKED_SITES,
    FOCUS_DURATION: STORAGE_KEYS.OPTIONS_FOCUS_DURATION,
    EMERGENCY_CODE: STORAGE_KEYS.OPTIONS_EMERGENCY_CODE,
    MAX_ATTEMPTS: STORAGE_KEYS.OPTIONS_MAX_ATTEMPTS
};

// Local state variables
let blockedSites = [];
let focusDuration = 25; // minutes
let emergencyRules = { code: '', maxAttempts: 3 };
let guardianLimits = { global: 10, overrides: {} };
let dailyUsage = {};
let timeSchedules = [];
let timeSchedulesEnabled = false;
let securityLogs = [];

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
const emergencyForm = document.getElementById('emergency-form');
const unlockCodeInput = document.getElementById('unlock-code');
const unlockCodeConfirm = document.getElementById('unlock-code-confirm');
const codeMatchStatus = document.getElementById('code-match-status');
const maxAttemptsInput = document.getElementById('max-attempts');
const emergencyStatus = document.getElementById('emergency-status');
// Emergency unlock panel elements
const sessionIndicator = document.getElementById('session-indicator');
const sessionStatusText = document.getElementById('session-status-text');
const emergencyUnlockPanel = document.getElementById('emergency-unlock-panel');
const emergencyUnlockInput = document.getElementById('emergency-unlock-input');
const emergencyUnlockBtn = document.getElementById('emergency-unlock-btn');
const unlockAttemptsInfo = document.getElementById('unlock-attempts-info');
const emergencyUnlockError = document.getElementById('emergency-unlock-error');
const logsContainer = document.getElementById('logs-container');
const refreshLogsBtn = document.getElementById('refresh-logs');
const saveAllBtn = document.getElementById('save-all');
const resetBtn = document.getElementById('reset');
// Risk score elements
const riskScoreEl = document.getElementById('risk-score');
const scoreCircle = document.getElementById('score-circle');
const scoreValue = document.getElementById('score-value');
const riskDescription = document.getElementById('risk-description');
const riskAdvice = document.getElementById('risk-advice');
const refreshRiskBtn = document.getElementById('refresh-risk');
const globalLimitInput = document.getElementById('global-limit');
const saveGuardianLimitBtn = document.getElementById('save-guardian-limit');
const guardianUsageBody = document.getElementById('guardian-usage-body');
const schedulesToggle = document.getElementById('schedules-toggle');
const schedulesContainer = document.getElementById('schedules-container');
const addScheduleBtn = document.getElementById('add-schedule-btn');
const exportUsageCsvBtn = document.getElementById('export-usage-csv');
const exportUsageJsonBtn = document.getElementById('export-usage-json');
const exportLogsCsvBtn = document.getElementById('export-logs-csv');
const exportLogsJsonBtn = document.getElementById('export-logs-json');

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
    updateEmergencyUnlockPanel();
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
        updateEmergencyUnlockPanel();
    }
    if (changes.failedUnlockAttempts) {
        updateEmergencyUnlockPanel();
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

// Emergency rules
async function saveEmergencyRules(e) {
    e.preventDefault();

    const code = unlockCodeInput.value;
    const confirmCode = unlockCodeConfirm.value;

    // Check if codes match when setting a new code
    if (code && code !== confirmCode) {
        codeMatchStatus.textContent = 'Codes do not match';
        codeMatchStatus.className = 'no-match';
        return;
    }

    if (code) {
        const { hash, salt } = await hashPassword(code);
        emergencyRules.code = hash;
        saveSetting('optionsEmergencyCodeSalt', salt);
        codeMatchStatus.textContent = '';
    } else {
        emergencyRules.code = ''; // Allow clearing
        saveSetting('optionsEmergencyCodeSalt', null);
    }

    emergencyRules.maxAttempts = parseInt(maxAttemptsInput.value) || 3;
    updateUI();
    saveSetting(OPTIONS_STORAGE_KEYS.EMERGENCY_CODE, emergencyRules.code);
    saveSetting(OPTIONS_STORAGE_KEYS.MAX_ATTEMPTS, emergencyRules.maxAttempts);

    // Clear inputs
    unlockCodeInput.value = '';
    unlockCodeConfirm.value = '';

    emergencyStatus.textContent = 'Settings saved successfully';
    emergencyStatus.style.color = 'var(--success-color)';
    setTimeout(() => {
        emergencyStatus.textContent = emergencyRules.code ? 'Master code configured' : '';
    }, 2000);
}

// Emergency unlock panel functionality
async function updateEmergencyUnlockPanel() {
    const { sessionEndTime, failedUnlockAttempts = 0, maxAttempts = 3 } = await chrome.storage.local.get([
        'sessionEndTime',
        STORAGE_KEYS.FAILED_UNLOCK_ATTEMPTS,
        STORAGE_KEYS.MAX_ATTEMPTS
    ]);

    const hasActiveSession = sessionEndTime && Date.now() < sessionEndTime;

    if (hasActiveSession) {
        const remaining = sessionEndTime - Date.now();
        const mins = Math.floor(remaining / 60000);
        const secs = Math.floor((remaining % 60000) / 1000);

        sessionIndicator.className = 'active';
        sessionStatusText.textContent = `Active session - ${mins}m ${secs}s remaining`;
        emergencyUnlockPanel.style.display = 'block';

        const attemptsLeft = maxAttempts - failedUnlockAttempts;
        if (attemptsLeft > 0) {
            unlockAttemptsInfo.innerHTML = `<span style="color: var(--warning-color);">${attemptsLeft} attempt(s) remaining</span>`;
        } else {
            unlockAttemptsInfo.innerHTML = `<span style="color: var(--danger-color);">Maximum attempts exceeded. Wait for session to end.</span>`;
            emergencyUnlockBtn.disabled = true;
            emergencyUnlockInput.disabled = true;
        }
    } else {
        sessionIndicator.className = '';
        sessionStatusText.textContent = 'No active session';
        emergencyUnlockPanel.style.display = 'none';
    }
}

async function performEmergencyUnlock() {
    const password = emergencyUnlockInput.value;
    if (!password) {
        emergencyUnlockError.textContent = 'Please enter your master code';
        emergencyUnlockError.style.display = 'block';
        return;
    }

    emergencyUnlockBtn.disabled = true;
    emergencyUnlockBtn.textContent = 'Unlocking...';

    chrome.runtime.sendMessage({
        type: 'EMERGENCY_UNLOCK',
        payload: { password }
    }, (response) => {
        if (response && response.success) {
            emergencyUnlockError.style.display = 'none';
            emergencyUnlockInput.value = '';
            updateEmergencyUnlockPanel();
            checkSessionStatus();

            // Show success message
            sessionStatusText.textContent = 'Session ended successfully';
            sessionIndicator.className = '';
        } else {
            emergencyUnlockError.textContent = response?.error || 'Invalid code. Please try again.';
            emergencyUnlockError.style.display = 'block';
            emergencyUnlockInput.value = '';
            updateEmergencyUnlockPanel();
        }

        emergencyUnlockBtn.disabled = false;
        emergencyUnlockBtn.textContent = 'Unlock Now';
    });
}

// Code confirmation matching
function checkCodeMatch() {
    const code = unlockCodeInput.value;
    const confirmCode = unlockCodeConfirm.value;

    if (!code && !confirmCode) {
        codeMatchStatus.textContent = '';
        codeMatchStatus.className = '';
        return;
    }

    if (code && confirmCode) {
        if (code === confirmCode) {
            codeMatchStatus.textContent = 'Codes match';
            codeMatchStatus.className = 'match';
        } else {
            codeMatchStatus.textContent = 'Codes do not match';
            codeMatchStatus.className = 'no-match';
        }
    }
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
async function renderRiskScore() {
    // Fetch detailed risk data
    const [riskResponse, logsResponse] = await Promise.all([
        new Promise(resolve => chrome.runtime.sendMessage({ type: 'GET_RISK_SCORE' }, resolve)),
        new Promise(resolve => chrome.runtime.sendMessage({ type: 'GET_LOGS' }, resolve))
    ]);

    const { sessionEndTime, sessionTotalDuration, failedUnlockAttempts = 0 } = await chrome.storage.local.get([
        'sessionEndTime',
        'sessionTotalDuration',
        STORAGE_KEYS.FAILED_UNLOCK_ATTEMPTS
    ]);

    if (riskResponse && riskResponse.success) {
        const score = riskResponse.score;

        // Update main score display
        if (scoreValue) scoreValue.textContent = score;
        scoreCircle.style.setProperty('--score-percent', `${score}%`);

        let riskLevel = 'low-risk';
        let description = 'Low Risk';
        let advice = 'Great job! Your focus habits are healthy. Keep maintaining your current routine.';

        if (score >= 70) {
            riskLevel = 'high-risk';
            description = 'High Risk';
            advice = 'Your distraction patterns suggest difficulty focusing. Consider shorter sessions, removing more sites from blocklist, or using strict schedules.';
        } else if (score >= 40) {
            riskLevel = 'medium-risk';
            description = 'Medium Risk';
            advice = 'You show some distraction tendencies. Try to complete full sessions and avoid accessing blocked sites during focus time.';
        }

        scoreCircle.className = `score-circle ${riskLevel}`;
        riskDescription.textContent = description;
        if (riskAdvice) riskAdvice.textContent = advice;

        // Calculate individual factors for breakdown
        const logs = logsResponse?.logs || [];
        const now = new Date();
        const last24h = logs.filter(log => {
            const logTime = new Date(log.timestamp);
            return (now - logTime) < (24 * 60 * 60 * 1000);
        });
        const last3Days = logs.filter(log => {
            const logTime = new Date(log.timestamp);
            return (now - logTime) < (72 * 60 * 60 * 1000);
        });

        // Factor 1: Blocked attempts
        const blockedAttempts = last24h.filter(log => log.event === 'site_blocked').length;
        const blockedScore = Math.min(blockedAttempts * 10, 30);
        updateRiskFactor('blocked', blockedScore, 30);

        // Factor 2: Time of day
        const hour = now.getHours();
        const timeScore = (hour >= 22 || hour <= 5) ? 20 : 0;
        updateRiskFactor('time', timeScore, 20);

        // Factor 3: Session quality
        let sessionScore = 0;
        if (sessionEndTime && Date.now() < sessionEndTime && sessionTotalDuration) {
            const durationMins = sessionTotalDuration / (60 * 1000);
            if (durationMins < 10) {
                sessionScore = 15;
            } else if (durationMins >= 45) {
                sessionScore = -10; // This is a bonus
            }
        }
        updateRiskFactor('session', Math.max(0, sessionScore), 15);

        // Factor 4: Failed unlocks
        const unlockScore = Math.min(failedUnlockAttempts * 15, 45);
        updateRiskFactor('unlock', unlockScore, 45);

        // Factor 5: Consistency bonus
        const completedSessions = last3Days.filter(log => log.event === 'session_ended').length;
        let consistencyBonus = 0;
        if (completedSessions >= 5) {
            consistencyBonus = 15;
        } else if (completedSessions >= 2) {
            consistencyBonus = 5;
        }
        updateRiskFactor('consistency', consistencyBonus, 15, true);

        // Update statistics
        updateFocusStatistics(logs, last24h, last3Days, completedSessions);

    } else {
        riskDescription.textContent = 'Failed to calculate risk score';
        if (riskAdvice) riskAdvice.textContent = '';
    }
}

function updateRiskFactor(factorId, points, maxPoints, isBonus = false) {
    const scoreEl = document.getElementById(`factor-${factorId}-score`);
    const fillEl = document.getElementById(`factor-${factorId}-fill`);

    if (scoreEl && fillEl) {
        const percentage = Math.abs(points) / maxPoints * 100;
        fillEl.style.width = `${Math.min(percentage, 100)}%`;

        if (isBonus) {
            scoreEl.textContent = points > 0 ? `-${points} pts` : '0 pts';
            scoreEl.className = 'risk-factor-score bonus';
        } else {
            scoreEl.textContent = `+${points} pts`;
            scoreEl.className = 'risk-factor-score';
        }
    }
}

function updateFocusStatistics(allLogs, last24h, last3Days, completedSessions) {
    // Sessions completed in 3 days
    const sessionsCompletedEl = document.getElementById('stat-sessions-completed');
    if (sessionsCompletedEl) sessionsCompletedEl.textContent = completedSessions;

    // Sites blocked today
    const blockedTodayEl = document.getElementById('stat-blocked-today');
    if (blockedTodayEl) {
        const blockedToday = last24h.filter(log => log.event === 'site_blocked').length;
        blockedTodayEl.textContent = blockedToday;
    }

    // Current streak (consecutive days with completed sessions)
    const streakEl = document.getElementById('stat-current-streak');
    if (streakEl) {
        const streak = calculateStreak(allLogs);
        streakEl.textContent = streak;
    }

    // Average session length
    const avgSessionEl = document.getElementById('stat-avg-session');
    if (avgSessionEl) {
        const sessionStarts = last3Days.filter(log => log.event === 'session_started');
        if (sessionStarts.length > 0) {
            // Calculate average from details if available
            let totalMins = 0;
            let count = 0;
            sessionStarts.forEach(log => {
                if (log.details && log.details.duration) {
                    totalMins += log.details.duration;
                    count++;
                }
            });
            if (count > 0) {
                avgSessionEl.textContent = `${Math.round(totalMins / count)}m`;
            } else {
                avgSessionEl.textContent = '--';
            }
        } else {
            avgSessionEl.textContent = '--';
        }
    }
}

function calculateStreak(logs) {
    // Get unique days with completed sessions
    const sessionDays = new Set();
    logs.filter(log => log.event === 'session_ended').forEach(log => {
        const date = new Date(log.timestamp).toDateString();
        sessionDays.add(date);
    });

    // Check consecutive days from today
    let streak = 0;
    const today = new Date();

    for (let i = 0; i < 365; i++) {
        const checkDate = new Date(today);
        checkDate.setDate(today.getDate() - i);
        const dateStr = checkDate.toDateString();

        if (sessionDays.has(dateStr)) {
            streak++;
        } else if (i > 0) {
            // Skip today if no session yet, but break on past days without sessions
            break;
        }
    }

    return streak;
}

function refreshRiskScore() {
    renderRiskScore();
}

// UI updates
function updateUI() {
    currentDuration.textContent = `Current: ${focusDuration} minutes`;
    emergencyStatus.textContent = emergencyRules.code ? 'Master code configured' : '';
    emergencyStatus.style.color = emergencyRules.code ? 'var(--success-color)' : 'var(--text-secondary)';
    maxAttemptsInput.value = emergencyRules.maxAttempts;
}

// Settings persistence
async function loadSettings() {
    try {
        const result = await chrome.storage.local.get([
            OPTIONS_STORAGE_KEYS.BLOCKED_SITES,
            OPTIONS_STORAGE_KEYS.FOCUS_DURATION,
            OPTIONS_STORAGE_KEYS.EMERGENCY_CODE,
            OPTIONS_STORAGE_KEYS.MAX_ATTEMPTS
        ]);
        blockedSites = result[OPTIONS_STORAGE_KEYS.BLOCKED_SITES] || [];
        focusDuration = result[OPTIONS_STORAGE_KEYS.FOCUS_DURATION] || 25;
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
        emergencyRules = { code: '', maxAttempts: 3 };
        renderBlocklist();
        updateUI();
        renderLogs();
        renderRiskScore();
        try {
            await chrome.storage.local.remove([
                OPTIONS_STORAGE_KEYS.BLOCKED_SITES,
                OPTIONS_STORAGE_KEYS.FOCUS_DURATION,
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
    emergencyForm.addEventListener('submit', saveEmergencyRules);

    // Emergency unlock panel listeners
    if (emergencyUnlockBtn) {
        emergencyUnlockBtn.addEventListener('click', performEmergencyUnlock);
    }
    if (unlockCodeInput && unlockCodeConfirm) {
        unlockCodeInput.addEventListener('input', checkCodeMatch);
        unlockCodeConfirm.addEventListener('input', checkCodeMatch);
    }

    refreshLogsBtn.addEventListener('click', refreshLogs);
    saveAllBtn.addEventListener('click', saveAllSettings);
    resetBtn.addEventListener('click', resetSettings);
    refreshRiskBtn.addEventListener('click', refreshRiskScore);
    saveGuardianLimitBtn.addEventListener('click', saveGuardianLimit);

    // Time schedules
    schedulesToggle.addEventListener('change', toggleTimeSchedules);
    addScheduleBtn.addEventListener('click', addSchedule);

    // Export buttons
    exportUsageCsvBtn.addEventListener('click', () => exportUsageData('csv'));
    exportUsageJsonBtn.addEventListener('click', () => exportUsageData('json'));
    exportLogsCsvBtn.addEventListener('click', () => exportLogsData('csv'));
    exportLogsJsonBtn.addEventListener('click', () => exportLogsData('json'));
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
    // Use centralized DISTRACTING_SITES from config.js

    // Merge known sites with any other usage data
    const allDomains = new Set([...DISTRACTING_SITES, ...Object.keys(dailyUsage)]);

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

// ==========================================
// Time-Based Schedules Functions
// ==========================================

function toggleTimeSchedules() {
    timeSchedulesEnabled = schedulesToggle.checked;
    chrome.storage.local.set({ [STORAGE_KEYS.TIME_SCHEDULES_ENABLED]: timeSchedulesEnabled });
    updateSchedulesUI();
}

function updateSchedulesUI() {
    schedulesContainer.style.opacity = timeSchedulesEnabled ? '1' : '0.5';
    schedulesContainer.style.pointerEvents = timeSchedulesEnabled ? 'auto' : 'none';
}

function addSchedule() {
    const newSchedule = {
        id: Date.now(),
        name: 'New Schedule',
        startHour: 9,
        endHour: 17,
        limitMultiplier: 0.5,
        enabled: true
    };
    timeSchedules.push(newSchedule);
    saveTimeSchedules();
    renderTimeSchedules();
}

function removeSchedule(id) {
    timeSchedules = timeSchedules.filter(s => s.id !== id);
    saveTimeSchedules();
    renderTimeSchedules();
}

function updateSchedule(id, field, value) {
    const schedule = timeSchedules.find(s => s.id === id);
    if (schedule) {
        schedule[field] = value;
        saveTimeSchedules();
    }
}

function saveTimeSchedules() {
    chrome.storage.local.set({ [STORAGE_KEYS.TIME_SCHEDULES]: timeSchedules });
}

async function loadTimeSchedules() {
    const result = await chrome.storage.local.get([
        STORAGE_KEYS.TIME_SCHEDULES,
        STORAGE_KEYS.TIME_SCHEDULES_ENABLED
    ]);
    timeSchedules = result[STORAGE_KEYS.TIME_SCHEDULES] || [];
    timeSchedulesEnabled = result[STORAGE_KEYS.TIME_SCHEDULES_ENABLED] || false;
    schedulesToggle.checked = timeSchedulesEnabled;
    renderTimeSchedules();
    updateSchedulesUI();
}

function renderTimeSchedules() {
    schedulesContainer.innerHTML = '';

    if (timeSchedules.length === 0) {
        schedulesContainer.innerHTML = '<p style="color: var(--text-secondary); font-size: 13px; padding: 12px; text-align: center;">No schedules configured. Click "Add Schedule" to create one.</p>';
        return;
    }

    timeSchedules.forEach(schedule => {
        const scheduleDiv = document.createElement('div');
        scheduleDiv.className = 'schedule-item';
        scheduleDiv.style.cssText = 'background: rgba(0,0,0,0.2); padding: 16px; border-radius: 8px; margin-bottom: 12px; border: 1px solid var(--glass-border);';

        scheduleDiv.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 12px;">
                <input type="text" value="${schedule.name}"
                    style="background: transparent; border: none; color: white; font-size: 14px; font-weight: 500; width: 60%;"
                    onchange="updateSchedule(${schedule.id}, 'name', this.value)">
                <label style="display: flex; align-items: center; gap: 8px; font-size: 13px;">
                    <input type="checkbox" ${schedule.enabled ? 'checked' : ''}
                        onchange="updateSchedule(${schedule.id}, 'enabled', this.checked)">
                    <span>Enabled</span>
                </label>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; margin-bottom: 12px;">
                <div>
                    <label style="display: block; font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">Start Hour</label>
                    <input type="number" min="0" max="23" value="${schedule.startHour}"
                        style="width: 100%; padding: 6px; background: rgba(0,0,0,0.3); border: 1px solid var(--glass-border); border-radius: 4px; color: white;"
                        onchange="updateSchedule(${schedule.id}, 'startHour', parseInt(this.value))">
                </div>
                <div>
                    <label style="display: block; font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">End Hour</label>
                    <input type="number" min="0" max="23" value="${schedule.endHour}"
                        style="width: 100%; padding: 6px; background: rgba(0,0,0,0.3); border: 1px solid var(--glass-border); border-radius: 4px; color: white;"
                        onchange="updateSchedule(${schedule.id}, 'endHour', parseInt(this.value))">
                </div>
                <div>
                    <label style="display: block; font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">Limit Multiplier</label>
                    <input type="number" min="0.1" max="2" step="0.1" value="${schedule.limitMultiplier}"
                        style="width: 100%; padding: 6px; background: rgba(0,0,0,0.3); border: 1px solid var(--glass-border); border-radius: 4px; color: white;"
                        onchange="updateSchedule(${schedule.id}, 'limitMultiplier', parseFloat(this.value))">
                </div>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 12px; color: var(--text-secondary);">
                    ${schedule.startHour}:00 - ${schedule.endHour}:00
                    (${Math.floor((schedule.limitMultiplier * 100))}% of base limit)
                </span>
                <button onclick="removeSchedule(${schedule.id})" class="btn secondary small"
                    style="padding: 4px 12px; font-size: 12px;">Remove</button>
            </div>
        `;

        schedulesContainer.appendChild(scheduleDiv);
    });
}

// Make functions globally available for inline event handlers
window.updateSchedule = updateSchedule;
window.removeSchedule = removeSchedule;

// ==========================================
// Data Export Functions
// ==========================================

function exportUsageData(format) {
    const data = Object.entries(dailyUsage).map(([domain, seconds]) => ({
        domain,
        timeSpentSeconds: seconds,
        timeSpentMinutes: Math.floor(seconds / 60),
        limit: guardianLimits.overrides[domain] !== undefined
            ? guardianLimits.overrides[domain]
            : guardianLimits.global,
        date: new Date().toISOString().split('T')[0]
    }));

    if (format === 'csv') {
        exportAsCSV(data, 'usage-data', ['domain', 'timeSpentMinutes', 'limit', 'date']);
    } else {
        exportAsJSON(data, 'usage-data');
    }
}

function exportLogsData(format) {
    chrome.runtime.sendMessage({ type: 'GET_LOGS' }, (response) => {
        if (response.success) {
            const logs = response.logs;

            if (format === 'csv') {
                exportAsCSV(logs, 'security-logs', ['timestamp', 'type', 'event']);
            } else {
                exportAsJSON(logs, 'security-logs');
            }
        } else {
            alert('Failed to load logs for export');
        }
    });
}

function exportAsCSV(data, filename, fields) {
    if (data.length === 0) {
        alert('No data to export');
        return;
    }

    // Create CSV header
    const headers = fields || Object.keys(data[0]);
    let csvContent = headers.join(',') + '\n';

    // Add rows
    data.forEach(item => {
        const row = headers.map(header => {
            const value = item[header] || '';
            // Escape quotes and wrap in quotes if contains comma
            const stringValue = String(value);
            if (stringValue.includes(',') || stringValue.includes('"')) {
                return '"' + stringValue.replace(/"/g, '""') + '"';
            }
            return stringValue;
        });
        csvContent += row.join(',') + '\n';
    });

    downloadFile(csvContent, `${filename}-${new Date().toISOString().split('T')[0]}.csv`, 'text/csv');
}

function exportAsJSON(data, filename) {
    const jsonContent = JSON.stringify(data, null, 2);
    downloadFile(jsonContent, `${filename}-${new Date().toISOString().split('T')[0]}.json`, 'application/json');
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

// ==========================================
// Update loadSettings to include schedules
// ==========================================

// Initialize on load
document.addEventListener('DOMContentLoaded', async () => {
    await init();
    await loadTimeSchedules();
});