// popup.js - Popup UI for Cognitive Defense extension

// Local state
let sessionActive = false;
let timerInterval = null;
let sessionStartTime = null;
let blockEnabled = false;
let guardianEnabled = false;

// DOM elements
const timerDisplay = document.getElementById('timer-display');
const startBtn = document.getElementById('start-btn');
const stopBtn = document.getElementById('stop-btn');
const modeStatus = document.getElementById('mode-status');
const blockToggle = document.getElementById('block-toggle');
const guardianToggle = document.getElementById('guardian-toggle');
const guardianStats = document.getElementById('guardian-stats');
const dashboardLink = document.getElementById('dashboard-link');
const progressCircle = document.querySelector('.progress-ring__circle');

// Modals
const startModal = document.getElementById('start-modal');
const unlockModal = document.getElementById('unlock-modal');
const sessionPwdInput = document.getElementById('session-password');
const unlockPwdInput = document.getElementById('unlock-password');
const unlockError = document.getElementById('unlock-error');
const confirmStartBtn = document.getElementById('confirm-start');
const cancelStartBtn = document.getElementById('cancel-start');
const confirmStopBtn = document.getElementById('confirm-stop');
const cancelStopBtn = document.getElementById('cancel-stop');

// Incognito Elements
const incognitoWarning = document.getElementById('incognito-warning');
const fixIncognitoBtn = document.getElementById('fix-incognito-btn');
const incognitoModal = document.getElementById('incognito-modal');
const openExtensionsBtn = document.getElementById('open-extensions-btn');
const closeIncognitoModalBtn = document.getElementById('close-incognito-modal');

// Guardian Modals
const guardianSetupModal = document.getElementById('guardian-setup-modal');
const guardianUnlockModal = document.getElementById('guardian-unlock-modal');
const guardianSetupPwd = document.getElementById('guardian-setup-password');
const guardianSaveBtn = document.getElementById('guardian-save-btn');
const guardianCancelSetup = document.getElementById('guardian-cancel-setup');

const guardianUnlockPwd = document.getElementById('guardian-unlock-password');
const guardianUnlockErr = document.getElementById('guardian-unlock-error');
const guardianConfirmUnlock = document.getElementById('guardian-confirm-unlock');
const guardianCancelUnlock = document.getElementById('guardian-cancel-unlock');



// Constants
const RADIUS = 52;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

// Initialize UI
function init() {
    setupRing();
    loadStateFromStorage();
    checkIncognitoAccess();
    setupEventListeners();
    updateSecurityStatus();
}

function setupRing() {
    progressCircle.style.strokeDasharray = `${CIRCUMFERENCE} ${CIRCUMFERENCE}`;
    progressCircle.style.strokeDashoffset = CIRCUMFERENCE;
}

function setProgress(percent) {
    const offset = CIRCUMFERENCE - (percent / 100) * CIRCUMFERENCE;
    progressCircle.style.strokeDashoffset = offset;
}

// Check Incognito Access
function checkIncognitoAccess() {
    chrome.extension.isAllowedIncognitoAccess((isAllowed) => {
        if (!isAllowed) {
            incognitoWarning.classList.remove('hidden');
        } else {
            incognitoWarning.classList.add('hidden');
        }
    });
}

// Load state from storage
async function loadStateFromStorage() {
    try {
        const result = await chrome.storage.local.get(['sessionEndTime', 'blockedSites', 'strictMode', 'sessionTotalDuration', 'timeGuardianEnabled', 'dailyUsage', 'timeGuardianLimits']);
        const sessionEndTime = result.sessionEndTime;
        const blockedSites = result.blockedSites || [];
        const strictMode = result.strictMode || false;
        const totalDuration = result.sessionTotalDuration;

        if (sessionEndTime && Date.now() < sessionEndTime) {
            sessionActive = true;
            startTimer(sessionEndTime, totalDuration);
        }

        blockEnabled = blockedSites.length > 0 || strictMode;
        guardianEnabled = result.timeGuardianEnabled || false;

        updateBlockToggle();
        updateGuardianUI(result.dailyUsage, result.timeGuardianLimits);
        updateUI();
    } catch (error) {
        console.warn('Failed to load state:', error);
    }
}

// Session Management
async function requestStartSession() {
    // strict check for incognito
    const isAllowed = await new Promise(resolve => chrome.extension.isAllowedIncognitoAccess(resolve));
    if (!isAllowed) {
        incognitoModal.classList.remove('hidden');
        return;
    }

    startModal.classList.remove('hidden');
    sessionPwdInput.value = '';
    sessionPwdInput.focus();
}

async function startSession() {
    const password = sessionPwdInput.value;
    if (!password) return; // Add validation UI?

    try {
        const result = await chrome.storage.local.get([
            'optionsBlockedSites',
            'optionsFocusDuration',
            'optionsStrictMode',
            'optionsMaxAttempts'
        ]);
        const blockedSites = result.optionsBlockedSites || [];
        const duration = result.optionsFocusDuration || 25;
        const strictMode = result.optionsStrictMode || false;
        const maxAttempts = result.optionsMaxAttempts || 3;

        chrome.runtime.sendMessage({
            type: 'START_SESSION',
            payload: { duration, password, blockedSites, strictMode, maxAttempts }
        }, (response) => {
            if (response && response.success) {
                sessionActive = true;
                blockEnabled = blockedSites.length > 0 || strictMode;
                startModal.classList.add('hidden');

                const endTime = Date.now() + (duration * 60 * 1000);
                startTimer(endTime, duration * 60 * 1000);
                updateBlockToggle();
                updateUI();
            } else {
                alert('Failed to start session: ' + (response ? response.error : 'Unknown error'));
            }
        });
    } catch (error) {
        alert('Failed to load settings: ' + error.message);
    }
}

// Stop Session
function requestStopSession() {
    unlockModal.classList.remove('hidden');
    unlockPwdInput.value = '';
    unlockError.classList.add('hidden');
    unlockPwdInput.focus();
}

function stopSession() {
    const password = unlockPwdInput.value;
    if (!password) return;

    chrome.runtime.sendMessage({
        type: 'EMERGENCY_UNLOCK',
        payload: { password }
    }, (response) => {
        if (response && response.success) {
            sessionActive = false;
            blockEnabled = false;
            updateBlockToggle();

            clearInterval(timerInterval);
            timerInterval = null;
            setProgress(0);
            timerDisplay.textContent = '00:00:00';

            unlockModal.classList.add('hidden');
            updateUI();
        } else {
            unlockError.classList.remove('hidden');
            unlockPwdInput.value = '';
        }
    });
}

// Timer
function startTimer(endTime, totalDuration) {
    if (timerInterval) clearInterval(timerInterval);

    const update = () => {
        const now = Date.now();
        const diff = endTime - now;

        if (diff <= 0) {
            clearInterval(timerInterval);
            timerDisplay.textContent = '00:00:00';
            sessionActive = false;
            updateUI();
            return;
        }

        const totalSeconds = Math.floor(diff / 1000);
        const h = Math.floor(totalSeconds / 3600);
        const m = Math.floor((totalSeconds % 3600) / 60);
        const s = totalSeconds % 60;

        timerDisplay.textContent = `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;

        // Progress calculation
        // Default to 25m if totalDuration is missing (fallback)
        const maxTime = totalDuration || (25 * 60 * 1000);
        const progress = Math.min(100, (diff / maxTime) * 100);
        setProgress(progress);
    };

    update();
    timerInterval = setInterval(update, 1000);
}

// UI State
function updateUI() {
    if (sessionActive) {
        startBtn.classList.add('hidden');
        stopBtn.classList.remove('hidden');
        dashboardLink.style.pointerEvents = 'none';
        dashboardLink.style.opacity = '0.5';
        dashboardLink.textContent = 'Dashboard Locked';
        modeStatus.textContent = 'Focus';
        modeStatus.className = 'status-badge focus';
        blockToggle.disabled = true;
    } else {
        startBtn.classList.remove('hidden');
        stopBtn.classList.add('hidden');
        dashboardLink.style.display = 'block'; // Restore display if it was hidden
        dashboardLink.style.pointerEvents = 'auto';
        dashboardLink.style.opacity = '1';
        dashboardLink.textContent = 'Dashboard';
        modeStatus.textContent = 'Break';
        modeStatus.className = 'status-badge break';
        blockToggle.disabled = false;
    }
}

// Toggle
function toggleBlock() {
    if (sessionActive) return;

    // Strict incognito check
    chrome.extension.isAllowedIncognitoAccess(async (isAllowed) => {
        if (!isAllowed) {
            incognitoModal.classList.remove('hidden');
            // Revert checkbox
            blockToggle.checked = !blockToggle.checked;
            return;
        }

        blockEnabled = blockToggle.checked;

        let blockedSites = [];
        let strictMode = false;

        if (blockEnabled) {
            const settings = await chrome.storage.local.get(['optionsBlockedSites', 'optionsStrictMode']);
            blockedSites = settings.optionsBlockedSites || [];
            strictMode = settings.optionsStrictMode || false;
        }

        chrome.runtime.sendMessage({
            type: 'DYNAMIC_BLOCK',
            payload: { blockedSites, strictMode }
        }, (response) => {
            if (!response || !response.success) {
                blockToggle.checked = !blockEnabled;
                blockEnabled = !blockEnabled;
            }
        });
    });
}

function updateBlockToggle() {
    blockToggle.checked = blockEnabled;
    blockToggle.disabled = sessionActive;
}

// Time Guardian
// Time Guardian
async function toggleGuardian(e) {
    const isEnabling = guardianToggle.checked;

    if (isEnabling) {
        // Turning ON
        // Check if we have a GUARDIAN password set?
        // Actually, the requirement is "enable with the new PASSWORD once it is disabled".
        // This implies we ALWAYS want to set a new password when enabling, if one isn't currently active?
        // But if it's disabled, the password should have been cleared.
        // So we just check if one exists. If not, prompt.
        const { guardianPasswordHash } = await chrome.storage.local.get('guardianPasswordHash');

        if (!guardianPasswordHash) {
            // No password set - prompt to set one
            guardianSetupModal.classList.remove('hidden');
            guardianSetupPwd.value = '';
            guardianSetupPwd.focus();

            // Revert toggle until confirmed
            guardianToggle.checked = false;
        } else {
            // Password exists (shouldn't happen if we clear on disable, unless manual toggle or state mismatch)
            // Just enable
            enableGuardian();
        }
    } else {
        // Turning OFF
        const { guardianPasswordHash } = await chrome.storage.local.get('guardianPasswordHash');
        if (guardianPasswordHash) {
            // Protected - require unlock
            guardianUnlockModal.classList.remove('hidden');
            guardianUnlockPwd.value = '';
            guardianUnlockErr.classList.add('hidden');
            guardianUnlockPwd.focus();

            // Revert toggle until confirmed
            guardianToggle.checked = true;
        } else {
            // Not protected - just disable
            disableGuardian();
        }
    }
}

function enableGuardian() {
    guardianEnabled = true;
    guardianToggle.checked = true;
    chrome.storage.local.set({ timeGuardianEnabled: true });
    guardianStats.style.display = 'block';
    loadStateFromStorage();
}

function disableGuardian() {
    guardianEnabled = false;
    guardianToggle.checked = false;
    chrome.storage.local.set({ timeGuardianEnabled: false });
    guardianStats.style.display = 'none';
}

function saveGuardianPassword() {
    const pwd = guardianSetupPwd.value;
    if (!pwd) return;

    chrome.runtime.sendMessage({
        type: 'SET_GUARDIAN_PASSWORD',
        payload: { password: pwd }
    }, (response) => {
        if (response && response.success) {
            guardianSetupModal.classList.add('hidden');
            enableGuardian();
        } else alert('Failed to save password: ' + (response ? response.error : 'Unknown error'));
    });
}

function unlockGuardian() {
    const pwd = guardianUnlockPwd.value;
    chrome.runtime.sendMessage({
        type: 'VERIFY_GUARDIAN_PASSWORD',
        payload: { password: pwd }
    }, (response) => {
        if (response && response.success) {
            guardianUnlockModal.classList.add('hidden');
            // Clear the password now that we are disabling
            chrome.storage.local.remove(['guardianPasswordHash', 'guardianPasswordSalt']);
            disableGuardian();
        } else {
            guardianUnlockErr.classList.remove('hidden');
        }
    });
}

function updateGuardianUI(dailyUsage, limits) {
    guardianToggle.checked = guardianEnabled;

    if (guardianEnabled && dailyUsage) {
        guardianStats.style.display = 'block';

        // Calculate total time
        let totalSeconds = 0;
        Object.values(dailyUsage).forEach(s => totalSeconds += s);

        const m = Math.floor(totalSeconds / 60);
        guardianStats.textContent = `${m}m tracked today`;
    } else {
        guardianStats.style.display = 'none';
    }
}

// Listeners
function setupEventListeners() {
    startBtn.addEventListener('click', requestStartSession);
    confirmStartBtn.addEventListener('click', startSession);
    cancelStartBtn.addEventListener('click', () => startModal.classList.add('hidden'));

    stopBtn.addEventListener('click', requestStopSession);
    confirmStopBtn.addEventListener('click', stopSession);
    cancelStopBtn.addEventListener('click', () => unlockModal.classList.add('hidden'));

    // Incognito Listeners
    fixIncognitoBtn.addEventListener('click', () => incognitoModal.classList.remove('hidden'));
    closeIncognitoModalBtn.addEventListener('click', () => incognitoModal.classList.add('hidden'));
    openExtensionsBtn.addEventListener('click', () => {
        chrome.tabs.create({ url: 'chrome://extensions/?id=' + chrome.runtime.id });
    });



    guardianToggle.addEventListener('change', toggleGuardian);

    blockToggle.addEventListener('change', toggleBlock);

    dashboardLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (!sessionActive) {
            chrome.runtime.openOptionsPage();
        }
    });

    chrome.storage.onChanged.addListener((changes, namespace) => {
        if (namespace === 'local') {
            if (changes.sessionEndTime) {
                loadStateFromStorage();
            }
        }
    });
    // Guardian Listeners
    guardianSaveBtn.addEventListener('click', saveGuardianPassword);
    guardianCancelSetup.addEventListener('click', () => {
        guardianSetupModal.classList.add('hidden');
        // Toggle already reverted in toggleGuardian logic
    });

    guardianConfirmUnlock.addEventListener('click', unlockGuardian);
    guardianCancelUnlock.addEventListener('click', () => {
        guardianUnlockModal.classList.add('hidden');
    });

}

// Security Status Update
async function updateSecurityStatus() {
    const securityStatusBar = document.getElementById('security-status');
    const securityStatusText = document.getElementById('security-status-text');
    const threatsBadge = document.getElementById('threats-badge');

    try {
        const response = await new Promise((resolve) => {
            chrome.runtime.sendMessage({ type: 'SECURITY_GET_STATS' }, resolve);
        });

        if (response && response.core) {
            const threatsBlocked = response.core.threatsBlocked || 0;
            const alertsLast24h = response.alerts?.last24Hours || 0;

            if (alertsLast24h > 0) {
                securityStatusBar.className = 'security-status-bar warning';
                securityStatusText.textContent = `${alertsLast24h} alert(s) today`;
                threatsBadge.textContent = alertsLast24h;
                threatsBadge.classList.remove('hidden');
            } else if (threatsBlocked > 0) {
                securityStatusBar.className = 'security-status-bar';
                securityStatusText.textContent = `${threatsBlocked} threats blocked`;
                threatsBadge.classList.add('hidden');
            } else {
                securityStatusBar.className = 'security-status-bar';
                securityStatusText.textContent = 'Protected';
                threatsBadge.classList.add('hidden');
            }
        }
    } catch (error) {
        console.warn('[Popup] Failed to get security stats:', error);
    }
}

// Init
document.addEventListener('DOMContentLoaded', init);