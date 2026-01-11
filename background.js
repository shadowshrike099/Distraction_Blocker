// background.js - Service worker for Cognitive Defense extension

// Import centralized configuration
importScripts('config.js');

// Security module imports
importScripts(
  'security/securityConfig.js',
  'security/bloomFilter.js',
  'security/urlAnalyzer.js',
  'security/phishingDetector.js',
  'security/contentFilter.js',
  'security/privacyShield.js',
  'security/alertManager.js',
  'security/securityCore.js'
);

// Constants
const ALARM_NAME = 'focus-session-end';

// Time Guardian State
let timeGuardianEnabled = false;
let dailyUsage = {}; // { domain: seconds }
let guardianLimits = { global: DEFAULT_GLOBAL_LIMIT, overrides: {} };
let activeDomain = null;
let trackingInterval = null;
let lastTrackingTime = Date.now();


// Rate limiting for logs
let lastLogTime = 0;
const LOG_THROTTLE_MS = 1000;

// Global state for blocking
let currentBlockedSites = [];
let currentStrictMode = false;

// Web request listener for blocking (Removed for DNR migration)
/*
chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        // ... (Legacy code removed)
    },
    { urls: ["<all_urls>"] },
    ["blocking"]
);
*/

// Update blocking rules using declarativeNetRequest
async function updateBlockingRules(blockedSites, strictMode = false) {
    currentBlockedSites = blockedSites || [];
    currentStrictMode = strictMode || false;

    // 1. Get existing dynamic rules to remove them
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existingRules.map(rule => rule.id);

    // 2. Prepare new rules
    const addRules = [];
    let ruleId = 1;

    // Helper to add a rule
    const addBlockRule = (domainFilter) => {
        addRules.push({
            id: ruleId++,
            priority: 1,
            action: { type: "block" },
            condition: {
                urlFilter: domainFilter,
                resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest", "script", "image", "stylesheet", "other"]
            }
        });
    };

    // 3. Convert blockedSites to DNR rules
    for (const sitePattern of currentBlockedSites) {
        // Validate and clean domain
        let domain = '';
        try {
            // Handle various input formats
            let urlToParse = sitePattern;
            if (!urlToParse.startsWith('http')) {
                urlToParse = 'http://' + urlToParse.replace(/^\*:\/\/\*\./, '').replace(/^\*\./, '');
            }
            const urlObj = new URL(urlToParse);
            domain = urlObj.hostname;
        } catch (e) {
            console.warn('Skipping invalid domain pattern:', sitePattern);
            continue;
        }

        if (!domain || domain.includes('*') || domain.length < 3) {
            console.warn('Skipping potentially dangerous or invalid domain:', domain);
            continue;
        }

        // Special Case: Distraction-Free YouTube
        // If the user wants to block YouTube, we interpret it as "Distraction Free" mode
        // So we SKIP the network block and let content.js handle it
        if (domain.includes('youtube.com')) {
            console.log('Skipping DNR block for YouTube (Distraction Free Mode active)');
            continue;
        }

        // Block the domain and subdomains
        addBlockRule(`||${domain}^`);
    }

    // 4. Strict mode rules
    if (currentStrictMode) {
        // Use centralized strict mode sites config
        // YouTube excluded to allow Distraction-Free mode via content script
        for (const domain of STRICT_MODE_SITES) {
            addBlockRule(`||${domain}^`);
        }
    }

    // 5. Update rules
    try {
        await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: removeRuleIds,
            addRules: addRules
        });
        console.log('Blocking rules updated:', addRules.length, 'rules active');
    } catch (error) {
        console.error('Failed to update DNR rules:', error);
    }
}

// Initialize on install
chrome.runtime.onInstalled.addListener(() => {
    updateBlockingRules([]);
    enforceActiveSession();
    addSecurityLog('extension_startup', {});
    initTimeGuardian();
    setupMidnightAlarm();
    initTimeGuardian();
    setupMidnightAlarm();
    // Initialize security modules
    initializeSecurity();
});

// On startup
chrome.runtime.onStartup.addListener(() => {
    enforceActiveSession();
    addSecurityLog('extension_startup', {});
    initTimeGuardian();
    // Initialize security modules
    initializeSecurity();
});


// Message handling
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.type) {
        case 'START_SESSION':
            handleStartSession(message.payload).then(sendResponse);
            return true;
        case 'END_SESSION':
            handleEndSession().then(sendResponse);
            return true;
        case 'DYNAMIC_BLOCK':
            handleDynamicBlock(message.payload).then(sendResponse);
            return true;
        case 'EMERGENCY_UNLOCK':
            handleEmergencyUnlock(message.payload).then(sendResponse);
            return true;
        case 'SET_PASSWORD':
            handleSetPassword(message.payload).then(sendResponse);
            return true;
        case 'VERIFY_PASSWORD':
            handleVerifyPassword(message.payload).then(sendResponse);
            return true;
        case 'GET_LOGS':
            getSecurityLogs().then(sendResponse);
            return true;
        case 'GET_RISK_SCORE':
            getRiskScore().then(sendResponse);
            return true;
        case 'GUARDIAN_CHECK_LIMIT': // Content script asks if it should block
            checkGuardianLimit(message.payload).then(sendResponse);
            return true;
        case 'GUARDIAN_BYPASS':
            handleGuardianBypass(message.payload).then(sendResponse);
            return true;
        case 'SET_GUARDIAN_PASSWORD':
            handleSetGuardianPassword(message.payload).then(sendResponse);
            return true;
        case 'VERIFY_GUARDIAN_PASSWORD':
            handleVerifyGuardianPassword(message.payload).then(sendResponse);
            return true;
        // Security module message handlers
        case 'SECURITY_ANALYZE_URL':
            handleSecurityAnalyzeUrl(message.payload).then(sendResponse);
            return true;
        case 'SECURITY_ANALYZE_PAGE':
            handleSecurityAnalyzePage(message.payload).then(sendResponse);
            return true;
        case 'SECURITY_GET_STATS':
            handleGetSecurityStats().then(sendResponse);
            return true;
        case 'SECURITY_UPDATE_SETTINGS':
            handleUpdateSecuritySettings(message.payload).then(sendResponse);
            return true;
        case 'SECURITY_GET_SETTINGS':
            handleGetSecuritySettings().then(sendResponse);
            return true;
        case 'SECURITY_WHITELIST_ADD':
            handleWhitelistAdd(message.payload).then(sendResponse);
            return true;
        case 'SECURITY_WHITELIST_REMOVE':
            handleWhitelistRemove(message.payload).then(sendResponse);
            return true;
        case 'SECURITY_GET_ALERTS':
            handleGetSecurityAlerts().then(sendResponse);
            return true;
        case 'SECURITY_CLEAR_ALERTS':
            handleClearSecurityAlerts().then(sendResponse);
            return true;
        case 'SECURITY_SHOW_WARNING_REQUEST':
            handleSecurityShowWarningRequest(message.payload, sender).then(sendResponse);
            return true;
        case 'SECURITY_EXPORT_DATA':
            handleSecurityExportData().then(sendResponse);
            return true;
        case 'SECURITY_GET_WHITELIST':
            handleGetWhitelist().then(sendResponse);
            return true;
        default:
            sendResponse({ success: false, error: 'Unknown message type' });
    }
});

// Handle start session
async function handleStartSession({ duration, password, blockedSites, strictMode, maxAttempts = 3 }) {
    try {
        const durationMs = duration * 60 * 1000;
        const endTime = Date.now() + durationMs;
        const { hash, salt } = await hashPassword(password);

        await chrome.storage.local.set({
            [STORAGE_KEYS.SESSION_END_TIME]: endTime,
            'sessionTotalDuration': durationMs,
            [STORAGE_KEYS.PASSWORD_HASH]: hash,
            [STORAGE_KEYS.PASSWORD_SALT]: salt,
            [STORAGE_KEYS.BLOCKED_SITES]: blockedSites || [],
            [STORAGE_KEYS.STRICT_MODE]: strictMode || false,
            [STORAGE_KEYS.FAILED_UNLOCK_ATTEMPTS]: 0,
            [STORAGE_KEYS.MAX_ATTEMPTS]: maxAttempts
        });

        chrome.alarms.create(ALARM_NAME, { when: endTime });
        updateBlockingRules(blockedSites || [], strictMode);
        addSecurityLog('session_started', { duration, blockedSitesCount: blockedSites?.length || 0 });

        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Handle end session
async function handleEndSession() {
    try {
        chrome.alarms.clear(ALARM_NAME);

        // Notify user if session ended naturally (check if it was time)
        // For simplicity, we just notify "Session Ended" whenever this is called and it wasn't an emergency unlock?
        // Actually, handleEndSession is called by ALARM (natural) and EMERGENCY UNLOCK.
        // We can check if alarm fired it?
        // Let's just add a generic notification for now, or refine later.
        // The user request asked for: "Add toast/notification when session ends"

        await chrome.storage.local.remove([
            STORAGE_KEYS.SESSION_END_TIME,
            'sessionTotalDuration',
            STORAGE_KEYS.PASSWORD_HASH,
            STORAGE_KEYS.PASSWORD_SALT,
            STORAGE_KEYS.BLOCKED_SITES,
            STORAGE_KEYS.STRICT_MODE,
            STORAGE_KEYS.FAILED_UNLOCK_ATTEMPTS
        ]);
        updateBlockingRules([]);
        addSecurityLog('session_ended', {});

        // Simple notification
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon128.png',
            title: 'Cognitive Defense',
            message: 'Focus session ended.'
        });

        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Handle dynamic block updates
async function handleDynamicBlock({ blockedSites, strictMode }) {
    try {
        await chrome.storage.local.set({
            [STORAGE_KEYS.BLOCKED_SITES]: blockedSites,
            [STORAGE_KEYS.STRICT_MODE]: strictMode
        });
        updateBlockingRules(blockedSites, strictMode);
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Handle Set Password
async function handleSetPassword({ password }) {
    try {
        const { hash, salt } = await hashPassword(password);
        await chrome.storage.local.set({
            [STORAGE_KEYS.PASSWORD_HASH]: hash,
            [STORAGE_KEYS.PASSWORD_SALT]: salt
        });
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Handle Verify Password
async function handleVerifyPassword({ password }) {
    try {
        const result = await verifyPassword(password);
        return result;
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Handle emergency unlock
async function handleEmergencyUnlock({ password }) {
    try {
        const { passwordHash, failedUnlockAttempts = 0, maxAttempts = 3 } = await chrome.storage.local.get([
            STORAGE_KEYS.PASSWORD_HASH,
            STORAGE_KEYS.FAILED_UNLOCK_ATTEMPTS,
            STORAGE_KEYS.MAX_ATTEMPTS
        ]);

        // Check session password logic matches previous impl
        if (!passwordHash) {
            const { optionsEmergencyCode, optionsEmergencyCodeSalt } = await chrome.storage.local.get(['optionsEmergencyCode', 'optionsEmergencyCodeSalt']);
            if (optionsEmergencyCode) {
                const { hash: inputHash } = await hashPassword(password, optionsEmergencyCodeSalt);
                if (inputHash === optionsEmergencyCode) {
                    await handleEndSession();
                    addSecurityLog('unlock_attempt_success', { type: 'master_code' });
                    return { success: true };
                }
            }
            return { success: false, error: 'No active session or invalid code' };
        }

        if (failedUnlockAttempts >= maxAttempts) {
            addSecurityLog('unlock_attempt_failed', { attemptCount: failedUnlockAttempts, reason: 'max_attempts_exceeded' });
            return { success: false, error: 'Maximum unlock attempts exceeded' };
        }

        // Get session salt
        const { passwordSalt } = await chrome.storage.local.get(STORAGE_KEYS.PASSWORD_SALT);
        const { hash: inputHash } = await hashPassword(password, passwordSalt);

        if (inputHash === passwordHash) {
            await handleEndSession();
            addSecurityLog('unlock_attempt_success', {});
            return { success: true };
        } else {
            const { optionsEmergencyCode, optionsEmergencyCodeSalt } = await chrome.storage.local.get(['optionsEmergencyCode', 'optionsEmergencyCodeSalt']);
            if (optionsEmergencyCode) {
                const { hash: backupHash } = await hashPassword(password, optionsEmergencyCodeSalt);
                if (backupHash === optionsEmergencyCode) {
                    await handleEndSession();
                    addSecurityLog('unlock_attempt_success', { type: 'master_code_backup' });
                    return { success: true };
                }
            }

            const newAttempts = failedUnlockAttempts + 1;
            await chrome.storage.local.set({ [STORAGE_KEYS.FAILED_UNLOCK_ATTEMPTS]: newAttempts });
            addSecurityLog('unlock_attempt_failed', { attemptCount: newAttempts });
            return { success: false, error: 'Invalid password' };
        }
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Alarm listener
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === ALARM_NAME) {
        handleEndSession();
    }
});

// Enforce lock
async function enforceLock() {
    await handleEndSession();
    addSecurityLog('session_expired_lock', {});
}

// Check active session
async function enforceActiveSession() {
    const { sessionEndTime, blockedSites, strictMode } = await chrome.storage.local.get([
        STORAGE_KEYS.SESSION_END_TIME,
        STORAGE_KEYS.BLOCKED_SITES,
        STORAGE_KEYS.STRICT_MODE
    ]);

    if (sessionEndTime && Date.now() < sessionEndTime) {
        chrome.alarms.create(ALARM_NAME, { when: sessionEndTime });
        updateBlockingRules(blockedSites || [], strictMode);
    } else if (sessionEndTime) {
        enforceLock();
    }
}

// Hash password using Web Crypto API
// Hash password using PBKDF2
async function hashPassword(password, salt = null) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);

    // Generate or use provided salt
    let saltBuffer;
    if (salt) {
        // Convert hex string back to buffer
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

    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: checkSalt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );

    // Export the key to get a string representation (using raw export for simplicity in this context, or better, just digest)
    // Actually for password verification we usually just need the derived bits or a digest. 
    // Let's use deriveBits for consistency with a "hash".
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

// Verify password
async function verifyPassword(password) {
    try {
        const { passwordHash, passwordSalt } = await chrome.storage.local.get([
            STORAGE_KEYS.PASSWORD_HASH,
            STORAGE_KEYS.PASSWORD_SALT
        ]);

        if (!passwordHash) {
            return { success: false, error: 'No password set' };
        }

        const { hash: inputHash } = await hashPassword(password, passwordSalt);

        if (inputHash === passwordHash) {
            return { success: true };
        } else {
            return { success: false, error: 'Invalid password' };
        }
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// Security logging functions
async function addSecurityLog(event, details) {
    // Rate limit
    const now = Date.now();
    if (now - lastLogTime < LOG_THROTTLE_MS) {
        return; // Skip log if too frequent
    }
    lastLogTime = now;

    try {
        const { securityLogs = [] } = await chrome.storage.local.get(STORAGE_KEYS.SECURITY_LOGS);

        const logEntry = {
            timestamp: new Date().toISOString(),
            type: getLogType(event),
            event: event,
            details: details
        };

        securityLogs.push(logEntry);

        // Limit to 100 entries
        if (securityLogs.length > 100) {
            securityLogs.shift();
        }

        await chrome.storage.local.set({ [STORAGE_KEYS.SECURITY_LOGS]: securityLogs });
    } catch (error) {
        console.error('Failed to add security log:', error);
    }
}

function getLogType(event) {
    if (event.includes('session')) return 'security';
    if (event.includes('unlock')) return 'unlock';
    if (event.includes('extension')) return 'security';
    return 'access';
}

async function getSecurityLogs() {
    try {
        const { securityLogs = [] } = await chrome.storage.local.get(STORAGE_KEYS.SECURITY_LOGS);
        return { success: true, logs: securityLogs };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Risk scoring system
async function getRiskScore() {
    try {
        const {
            securityLogs = [],
            sessionEndTime,
            sessionTotalDuration,
            failedUnlockAttempts = 0
        } = await chrome.storage.local.get([
            STORAGE_KEYS.SECURITY_LOGS,
            STORAGE_KEYS.SESSION_END_TIME,
            'sessionTotalDuration',
            STORAGE_KEYS.FAILED_UNLOCK_ATTEMPTS
        ]);

        let score = 0;

        // 1. Frequency of blocked attempts (from logs)
        const recentLogs = securityLogs.filter(log => {
            const logTime = new Date(log.timestamp);
            const now = new Date();
            return (now - logTime) < (24 * 60 * 60 * 1000); // Last 24 hours
        });
        const blockedAttempts = recentLogs.filter(log => log.event === 'site_blocked').length;
        score += Math.min(blockedAttempts * 10, 30); // Up to 30 points

        // 2. Time of day (higher risk late night)
        const hour = new Date().getHours();
        if (hour >= 22 || hour <= 5) {
            score += 20; // Late night/early morning
        }

        // 3. Session Quality (Current Session)
        if (sessionEndTime && Date.now() < sessionEndTime) {
            // Check total duration if available
            if (sessionTotalDuration) {
                const durationMins = sessionTotalDuration / (60 * 1000);
                if (durationMins < 10) {
                    score += 15; // Penalty: Very short session (micromanaging?)
                } else if (durationMins >= 45) {
                    score -= 10; // Bonus: Deep work session
                }
            }
        }

        // 4. Repeated Failed Unlocks (High Risk Behavior)
        // Heavily penalize multiple failed attempts in current session
        if (failedUnlockAttempts > 0) {
            score += Math.min(failedUnlockAttempts * 15, 45); // +15 per fail, max 45
        }

        // 5. Consistency Bonus (Long-term behavior)
        // Check logs for successful session completions in last 3 days
        const threeDaysAgo = Date.now() - (72 * 60 * 60 * 1000);
        const completedSessions = securityLogs.filter(log => {
            return log.event === 'session_ended' && new Date(log.timestamp).getTime() > threeDaysAgo;
        }).length;

        if (completedSessions >= 5) {
            score -= 15; // Consistent user bonus
        } else if (completedSessions >= 2) {
            score -= 5;
        }

        // Clamp score to 0-100
        score = Math.max(0, Math.min(100, score));

        return { success: true, score: Math.round(score) };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// ==========================================
// Time Guardian Implementation
// ==========================================

async function initTimeGuardian() {
    const result = await chrome.storage.local.get([
        STORAGE_KEYS.TIME_GUARDIAN_ENABLED,
        STORAGE_KEYS.DAILY_USAGE,
        STORAGE_KEYS.GUARDIAN_LIMITS,
        STORAGE_KEYS.LAST_RESET_DATE
    ]);

    timeGuardianEnabled = result[STORAGE_KEYS.TIME_GUARDIAN_ENABLED] || false;
    dailyUsage = result[STORAGE_KEYS.DAILY_USAGE] || {};
    guardianLimits = result[STORAGE_KEYS.GUARDIAN_LIMITS] || { global: DEFAULT_GLOBAL_LIMIT, overrides: {} };

    console.log('[Guardian] Init:', { enabled: timeGuardianEnabled, usage: dailyUsage, limits: guardianLimits });

    // Check reset
    const today = new Date().toDateString();
    if (result[STORAGE_KEYS.LAST_RESET_DATE] !== today) {
        dailyUsage = {};
        await chrome.storage.local.set({
            [STORAGE_KEYS.DAILY_USAGE]: dailyUsage,
            [STORAGE_KEYS.LAST_RESET_DATE]: today
        });
    }

    if (timeGuardianEnabled) {
        startGuardianTracking();
        injectGuardianScripts(); // Ensure open tabs get the script
    }
}

async function injectGuardianScripts() {
    const tabs = await chrome.tabs.query({ url: DISTRACTING_SITES.map(site => `*://*.${site}/*`) });
    for (const tab of tabs) {
        try {
            await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                files: ['content/guardian.js']
            });
        } catch (e) {
            // Script might already be there or cannot access tab
        }
    }
}

function setupMidnightAlarm() {
    chrome.alarms.create('guardian_daily_reset', {
        when: getNextMidnight(),
        periodInMinutes: 1440 // 24 hours
    });
}

function getNextMidnight() {
    const midnight = new Date();
    midnight.setHours(24, 0, 0, 0);
    return midnight.getTime();
}

function startGuardianTracking() {
    if (trackingInterval) clearInterval(trackingInterval);

    // Update active domain immediately
    updateActiveDomain();

    // Check every 1s
    trackingInterval = setInterval(trackCurrentTab, 1000);

    // Listeners
    chrome.tabs.onActivated.addListener(updateActiveDomain);
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
        if (changeInfo.url || changeInfo.status === 'complete') updateActiveDomain();
    });
    chrome.windows.onFocusChanged.addListener(updateActiveDomain);
}

function stopGuardianTracking() {
    if (trackingInterval) clearInterval(trackingInterval);
    trackingInterval = null;
    activeDomain = null;
    chrome.tabs.onActivated.removeListener(updateActiveDomain);
    chrome.windows.onFocusChanged.removeListener(updateActiveDomain);
    // Note: onUpdated logic difficult to remove cleanly without named function, 
    // but overhead is low if timeGuardianEnabled is checked inside.
}

async function updateActiveDomain() {
    if (!timeGuardianEnabled) return;

    try {
        // Get the truly active tab in the focused window
        const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });

        if (!tab || !tab.url) {
            activeDomain = null;
            return;
        }

        const urlObj = new URL(tab.url);
        const hostname = urlObj.hostname.replace('www.', '');

        // Check if it's a distracting site
        const isDistracting = DISTRACTING_SITES.some(site => hostname.endsWith(site));
        console.log('[Guardian] Active Tab:', tab.id, hostname, 'Is Distracting:', isDistracting);

        if (isDistracting) {
            activeDomain = hostname;
            checkLimitAndShowOverlay(activeDomain, tab.id); // Check immediately
        } else {
            activeDomain = null;
        }
    } catch (e) {
        console.warn('Error updating active domain:', e);
        activeDomain = null;
    }
}

async function checkLimitAndShowOverlay(domain, tabId = null) {
    if (!domain || !timeGuardianEnabled) return;

    // Get base limit
    let baseLimit = guardianLimits.overrides[domain] !== undefined
        ? guardianLimits.overrides[domain]
        : guardianLimits.global;

    // Apply time-based scheduling if enabled
    const { timeSchedulesEnabled, timeSchedules } = await chrome.storage.local.get([
        STORAGE_KEYS.TIME_SCHEDULES_ENABLED,
        STORAGE_KEYS.TIME_SCHEDULES
    ]);

    let actualLimit = baseLimit;
    if (timeSchedulesEnabled && timeSchedules) {
        const multiplier = getCurrentScheduleMultiplier(timeSchedules);
        actualLimit = Math.floor(baseLimit * multiplier);
    }

    const usage = dailyUsage[domain] || 0;

    // Debug
    // console.log(`Checking limit for ${domain}: ${usage}/${actualLimit}`);

    if (usage > actualLimit) {
        // If tabId not provided, verify we are targeting the CURRENT active tab
        let targetTabId = tabId;
        if (!targetTabId) {
            const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
            if (tab) targetTabId = tab.id;
        }

        if (targetTabId) {
            // Check for grace period
            const graceKey = `grace_${domain}`;
            const { [graceKey]: graceTime } = await chrome.storage.local.get(graceKey);

            if (!graceTime || Date.now() > graceTime) {
                chrome.tabs.sendMessage(targetTabId, {
                    type: 'GUARDIAN_SHOW_OVERLAY',
                    payload: {
                        timeSpent: usage,
                        limit: actualLimit,
                        domain: domain
                    }
                }).catch(() => {
                    // console.log('Could not send overlay to tab', targetTabId);
                });
            }
        }
    }
}

async function trackCurrentTab() {
    if (!activeDomain || !timeGuardianEnabled) return;

    // Increment usage
    if (!dailyUsage[activeDomain]) dailyUsage[activeDomain] = 0;
    dailyUsage[activeDomain]++;
    console.log('[Guardian] Tracking:', activeDomain, 'Usage:', dailyUsage[activeDomain]);

    // Save every 30s to storage to reduce I/O (or use a dirty flag, but simple is fine for now)
    if (dailyUsage[activeDomain] % 10 === 0) {
        chrome.storage.local.set({ [STORAGE_KEYS.DAILY_USAGE]: dailyUsage });
    }

    // Check limits
    checkLimitAndShowOverlay(activeDomain);
}

async function checkGuardianLimit({ domain }) {
    if (!timeGuardianEnabled) return { blocked: false };

    const usage = dailyUsage[domain] || 0;

    // Get base limit
    let baseLimit = guardianLimits.overrides[domain] !== undefined
        ? guardianLimits.overrides[domain]
        : guardianLimits.global;

    // Apply time-based scheduling if enabled
    const { timeSchedulesEnabled, timeSchedules } = await chrome.storage.local.get([
        STORAGE_KEYS.TIME_SCHEDULES_ENABLED,
        STORAGE_KEYS.TIME_SCHEDULES
    ]);

    let actualLimit = baseLimit;
    if (timeSchedulesEnabled && timeSchedules) {
        const multiplier = getCurrentScheduleMultiplier(timeSchedules);
        actualLimit = Math.floor(baseLimit * multiplier);
    }

    if (usage > actualLimit) {
        const graceKey = `grace_${domain}`;
        const { [graceKey]: graceTime } = await chrome.storage.local.get(graceKey);

        if (graceTime && Date.now() < graceTime) {
            return { blocked: false };
        }
        return { blocked: true, timeSpent: usage, limit: actualLimit };
    }
    return { blocked: false };
}

async function handleGuardianBypass({ domain }) {
    // Grant 5 minutes grace
    const graceTime = Date.now() + (5 * 60 * 1000);
    const graceKey = `grace_${domain}`;
    await chrome.storage.local.set({ [graceKey]: graceTime });
    return { success: true };
}

// Alarm handler for Midnight Reset
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'guardian_daily_reset') {
        dailyUsage = {};
        chrome.storage.local.set({
            [STORAGE_KEYS.DAILY_USAGE]: dailyUsage,
            [STORAGE_KEYS.LAST_RESET_DATE]: new Date().toDateString()
        });
        // Also clear grace periods?
    }
});

// Guardian Password Handlers
async function handleSetGuardianPassword({ password }) {
    try {
        const { hash, salt } = await hashPassword(password);
        await chrome.storage.local.set({
            [STORAGE_KEYS.GUARDIAN_PASSWORD_HASH]: hash,
            [STORAGE_KEYS.GUARDIAN_PASSWORD_SALT]: salt
        });
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function handleVerifyGuardianPassword({ password }) {
    try {
        const { guardianPasswordHash, guardianPasswordSalt } = await chrome.storage.local.get([
            STORAGE_KEYS.GUARDIAN_PASSWORD_HASH,
            STORAGE_KEYS.GUARDIAN_PASSWORD_SALT
        ]);

        if (!guardianPasswordHash) {
            return { success: false, error: 'No guardian password set' };
        }

        const { hash: inputHash } = await hashPassword(password, guardianPasswordSalt);

        if (inputHash === guardianPasswordHash) {
            return { success: true };
        } else {
            return { success: false, error: 'Invalid password' };
        }
    } catch (e) {
        return { success: false, error: e.message };
    }
}


// Listener for settings changes from Options/Popup
chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'local') {
        if (changes[STORAGE_KEYS.TIME_GUARDIAN_ENABLED]) {
            timeGuardianEnabled = changes[STORAGE_KEYS.TIME_GUARDIAN_ENABLED].newValue;
            if (timeGuardianEnabled) startGuardianTracking();
            else stopGuardianTracking();
        }
        if (changes[STORAGE_KEYS.GUARDIAN_LIMITS]) {
            guardianLimits = changes[STORAGE_KEYS.GUARDIAN_LIMITS].newValue;
        }
    }
});


// ==========================================
// Security Module Integration
// ==========================================

// Security: URL interception via webNavigation
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only process main frame
    if (details.frameId !== 0) return;

    // Skip extension pages and chrome:// URLs
    if (details.url.startsWith('chrome') || details.url.startsWith('moz-extension')) return;

    try {
        // Check if security is initialized
        if (typeof analyzeUrlSecurity !== 'function') return;

        const result = await analyzeUrlSecurity(details.url);

        if (result.recommendation === 'BLOCK') {
            // Auto-add to blocklist and block the site
            await autoAddToBlocklist(details.url, result);

            // Show notification
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon128.png',
                title: '🚨 Threat Blocked',
                message: `Blocked: ${new URL(details.url).hostname}\nReason: ${result.flags[0]?.detail || 'Security threat detected'}`,
                priority: 2,
                requireInteraction: true
            });

            // Redirect to a blocked page
            chrome.tabs.update(details.tabId, {
                url: chrome.runtime.getURL('blocked.html') + '?url=' + encodeURIComponent(details.url) + '&reason=' + encodeURIComponent(result.flags[0]?.detail || 'Security threat')
            });

            // Log the alert
            if (typeof logSecurityAlert === 'function') {
                await logSecurityAlert(result);
            }
        } else if (result.recommendation === 'WARN') {
            // Show warning overlay for warnings
            if (typeof showThreatWarning === 'function') {
                showThreatWarning(details.tabId, result);
            }
        }

        // Clean tracking parameters
        if (typeof cleanTrackingParams === 'function') {
            const cleanResult = cleanTrackingParams(details.url);
            if (cleanResult.modified && cleanResult.cleanedUrl !== details.url) {
                chrome.tabs.update(details.tabId, { url: cleanResult.cleanedUrl });
            }
        }
    } catch (e) {
        console.warn('Security analysis error:', e);
    }
});

/**
 * Auto-add detected threat to the blocklist
 * @param {string} url - URL that was detected as threat
 * @param {Object} threatData - Threat analysis data
 */
async function autoAddToBlocklist(url, threatData) {
    try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname.replace(/^www\./, '');

        // Get current blocked sites from options
        const { optionsBlockedSites = [] } = await chrome.storage.local.get('optionsBlockedSites');

        // Check if already blocked
        if (optionsBlockedSites.some(site => site.includes(domain))) {
            console.log('[Security] Domain already in blocklist:', domain);
            return;
        }

        // Add to blocked sites
        optionsBlockedSites.push(domain);

        await chrome.storage.local.set({ optionsBlockedSites: optionsBlockedSites });

        // Update blocking rules if session is active or blocking is enabled
        const { sessionEndTime, blockedSites = [], strictMode = false } = await chrome.storage.local.get([
            'sessionEndTime', 'blockedSites', 'strictMode'
        ]);

        if (sessionEndTime && Date.now() < sessionEndTime) {
            // Session is active, update the active blocklist too
            blockedSites.push(domain);
            await chrome.storage.local.set({ blockedSites: blockedSites });
            updateBlockingRules(blockedSites, strictMode);
        } else {
            // No active session, just update DNR rules with the new site
            updateBlockingRules([domain], false);
        }

        console.log('[Security] Auto-added to blocklist:', domain);
        addSecurityLog('threat_auto_blocked', { domain, threatScore: threatData.threatScore, reason: threatData.flags[0]?.detail });

    } catch (error) {
        console.error('[Security] Failed to auto-add to blocklist:', error);
    }
}

// Security handler functions
async function handleSecurityAnalyzeUrl(payload) {
    try {
        if (typeof analyzeUrlSecurity === 'function') {
            return await analyzeUrlSecurity(payload.url);
        }
        return { error: 'Security module not initialized' };
    } catch (error) {
        return { error: error.message };
    }
}

async function handleSecurityAnalyzePage(pageData) {
    try {
        if (typeof analyzePageSecurity === 'function') {
            return await analyzePageSecurity(pageData);
        }
        return { error: 'Security module not initialized' };
    } catch (error) {
        return { error: error.message };
    }
}

async function handleGetSecurityStats() {
    try {
        if (typeof getSecurityStats === 'function') {
            return await getSecurityStats();
        }
        return { error: 'Security module not initialized' };
    } catch (error) {
        return { error: error.message };
    }
}

async function handleUpdateSecuritySettings(settings) {
    try {
        if (typeof updateSecuritySettings === 'function') {
            return await updateSecuritySettings(settings);
        }
        return { success: false, error: 'Security module not initialized' };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function handleGetSecuritySettings() {
    try {
        if (typeof getSecuritySettings === 'function') {
            return await getSecuritySettings();
        }
        return { error: 'Security module not initialized' };
    } catch (error) {
        return { error: error.message };
    }
}

async function handleWhitelistAdd(payload) {
    try {
        if (typeof addToWhitelist === 'function') {
            return { success: await addToWhitelist(payload.domain) };
        }
        return { success: false, error: 'Security module not initialized' };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function handleWhitelistRemove(payload) {
    try {
        if (typeof removeFromWhitelist === 'function') {
            return { success: await removeFromWhitelist(payload.domain) };
        }
        return { success: false, error: 'Security module not initialized' };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function handleGetSecurityAlerts() {
    try {
        if (typeof getAlertHistory === 'function') {
            return { success: true, alerts: getAlertHistory(50) };
        }
        return { success: false, error: 'Security module not initialized' };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function handleClearSecurityAlerts() {
    try {
        if (typeof clearAlertHistory === 'function') {
            await clearAlertHistory();
            return { success: true };
        }
        return { success: false, error: 'Security module not initialized' };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function handleSecurityShowWarningRequest(payload, sender) {
    try {
        if (typeof showThreatWarning === 'function' && sender.tab) {
            await showThreatWarning(sender.tab.id, payload.threatData);
            return { success: true };
        }
        return { success: false, error: 'Cannot show warning' };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function handleSecurityExportData() {
    try {
        if (typeof exportSecurityData === 'function') {
            return await exportSecurityData();
        }
        return { error: 'Security module not initialized' };
    } catch (error) {
        return { error: error.message };
    }
}

async function handleGetWhitelist() {
    try {
        if (typeof getWhitelist === 'function') {
            return { success: true, whitelist: getWhitelist() };
        }
        return { success: false, error: 'Security module not initialized' };
    } catch (error) {
        return { success: false, error: error.message };
    }
}
