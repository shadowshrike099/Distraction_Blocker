/**
 * @fileoverview Security Alert Manager
 * @description Handles threat classification, notifications, and warning overlays
 * @version 1.0.0
 */

// Module state
let alertSettings = null;
let alertHistory = [];

/**
 * Initialize the alert manager
 * @async
 * @returns {Promise<boolean>} Success status
 */
async function initAlertManager() {
  try {
    // Load saved settings and history
    const stored = await chrome.storage.local.get([
      SECURITY_STORAGE_KEYS.SETTINGS,
      SECURITY_STORAGE_KEYS.ALERTS
    ]);

    alertSettings = stored[SECURITY_STORAGE_KEYS.SETTINGS]?.alerts || DEFAULT_ALERT_SETTINGS;
    alertHistory = stored[SECURITY_STORAGE_KEYS.ALERTS] || [];

    console.log('[Security] Alert Manager initialized successfully');
    return true;
  } catch (error) {
    console.error('[Security] Failed to initialize Alert Manager:', error);
    return false;
  }
}

/**
 * Classify threat level based on score
 * @param {number} score - Threat score (0-100)
 * @returns {string} Threat level
 */
function classifyThreatLevel(score) {
  if (score >= THREAT_THRESHOLDS.CRITICAL) return THREAT_LEVELS.CRITICAL;
  if (score >= THREAT_THRESHOLDS.HIGH) return THREAT_LEVELS.HIGH;
  if (score >= THREAT_THRESHOLDS.MEDIUM) return THREAT_LEVELS.MEDIUM;
  if (score >= THREAT_THRESHOLDS.LOW) return THREAT_LEVELS.LOW;
  return THREAT_LEVELS.NONE;
}

/**
 * Get color scheme for threat level
 * @param {string} threatLevel - Threat level
 * @returns {Object} Color scheme
 */
function getThreatColors(threatLevel) {
  const schemes = {
    [THREAT_LEVELS.CRITICAL]: {
      primary: '#dc2626',
      secondary: '#fecaca',
      gradient: 'linear-gradient(135deg, #dc2626, #991b1b)',
      text: '#ffffff',
      icon: '🚨'
    },
    [THREAT_LEVELS.HIGH]: {
      primary: '#ea580c',
      secondary: '#fed7aa',
      gradient: 'linear-gradient(135deg, #ea580c, #c2410c)',
      text: '#ffffff',
      icon: '⚠️'
    },
    [THREAT_LEVELS.MEDIUM]: {
      primary: '#ca8a04',
      secondary: '#fef08a',
      gradient: 'linear-gradient(135deg, #ca8a04, #a16207)',
      text: '#ffffff',
      icon: '⚡'
    },
    [THREAT_LEVELS.LOW]: {
      primary: '#2563eb',
      secondary: '#bfdbfe',
      gradient: 'linear-gradient(135deg, #2563eb, #1d4ed8)',
      text: '#ffffff',
      icon: 'ℹ️'
    }
  };

  return schemes[threatLevel] || schemes[THREAT_LEVELS.MEDIUM];
}

/**
 * Create HTML for warning overlay
 * @param {Object} threatData - Threat analysis data
 * @returns {string} HTML string for overlay
 */
function createWarningOverlay(threatData) {
  const colors = getThreatColors(threatData.threatLevel);
  const flagsList = threatData.flags
    .slice(0, 5)
    .map(flag => `<li>${escapeHtml(flag.detail)}</li>`)
    .join('');

  return `
    <div id="security-warning-overlay" style="
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      background: rgba(0, 0, 0, 0.85);
      backdrop-filter: blur(8px);
      z-index: 2147483647;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    ">
      <div style="
        background: #1a1a2e;
        border-radius: 16px;
        padding: 40px;
        max-width: 560px;
        width: 90%;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        border: 2px solid ${colors.primary};
        animation: warningSlideIn 0.3s ease-out;
      ">
        <style>
          @keyframes warningSlideIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
          }
          @keyframes warningPulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
          }
          #security-warning-overlay * {
            box-sizing: border-box;
          }
        </style>

        <div style="text-align: center; margin-bottom: 24px;">
          <div style="
            font-size: 64px;
            margin-bottom: 16px;
            animation: warningPulse 2s infinite;
          ">${colors.icon}</div>
          <h1 style="
            color: ${colors.primary};
            font-size: 28px;
            font-weight: 700;
            margin: 0 0 8px 0;
          ">${threatData.threatLevel} Security Warning</h1>
          <p style="
            color: #9ca3af;
            font-size: 14px;
            margin: 0;
          ">Cognitive Defense has detected potential threats</p>
        </div>

        <div style="
          background: rgba(255, 255, 255, 0.05);
          border-radius: 12px;
          padding: 20px;
          margin-bottom: 24px;
        ">
          <div style="
            color: #e5e7eb;
            font-size: 14px;
            margin-bottom: 12px;
          ">
            <strong>URL:</strong>
            <span style="color: #9ca3af; word-break: break-all;">
              ${escapeHtml(truncateUrl(threatData.url, 60))}
            </span>
          </div>

          <div style="
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 16px;
          ">
            <div style="
              background: ${colors.gradient};
              color: ${colors.text};
              padding: 8px 16px;
              border-radius: 8px;
              font-weight: 600;
              font-size: 14px;
            ">
              Threat Score: ${threatData.threatScore}/100
            </div>
            <div style="
              flex: 1;
              height: 8px;
              background: #374151;
              border-radius: 4px;
              overflow: hidden;
            ">
              <div style="
                width: ${threatData.threatScore}%;
                height: 100%;
                background: ${colors.gradient};
                transition: width 0.5s ease;
              "></div>
            </div>
          </div>

          ${flagsList ? `
            <div style="color: #e5e7eb; font-size: 14px;">
              <strong>Detected Issues:</strong>
              <ul style="
                margin: 8px 0 0 0;
                padding-left: 20px;
                color: #9ca3af;
              ">${flagsList}</ul>
            </div>
          ` : ''}
        </div>

        <div style="
          display: flex;
          gap: 12px;
          justify-content: center;
        ">
          <button id="security-go-back" style="
            flex: 1;
            padding: 14px 24px;
            background: ${colors.gradient};
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
          " onmouseover="this.style.transform='translateY(-2px)';this.style.boxShadow='0 4px 12px ${colors.primary}40';" onmouseout="this.style.transform='none';this.style.boxShadow='none';">
            ← Go Back to Safety
          </button>

          ${threatData.recommendation !== RECOMMENDATIONS.BLOCK ? `
            <button id="security-proceed" style="
              padding: 14px 24px;
              background: transparent;
              color: #6b7280;
              border: 1px solid #374151;
              border-radius: 8px;
              font-size: 14px;
              cursor: pointer;
              transition: all 0.2s;
            " onmouseover="this.style.borderColor='#6b7280';this.style.color='#9ca3af';" onmouseout="this.style.borderColor='#374151';this.style.color='#6b7280';">
              Proceed Anyway
            </button>
          ` : ''}
        </div>

        <p style="
          text-align: center;
          color: #6b7280;
          font-size: 12px;
          margin-top: 20px;
          margin-bottom: 0;
        ">
          Protected by Cognitive Defense Security
        </p>
      </div>
    </div>
  `;
}

/**
 * Escape HTML entities
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return String(text).replace(/[&<>"']/g, m => map[m]);
}

/**
 * Truncate URL for display
 * @param {string} url - URL to truncate
 * @param {number} maxLength - Maximum length
 * @returns {string} Truncated URL
 */
function truncateUrl(url, maxLength) {
  if (url.length <= maxLength) return url;
  return url.substring(0, maxLength - 3) + '...';
}

/**
 * Show Chrome notification for threat
 * @async
 * @param {Object} threatData - Threat analysis data
 * @returns {Promise<string|null>} Notification ID or null
 */
async function showChromeNotification(threatData) {
  if (!alertSettings?.showNotifications) return null;

  try {
    const colors = getThreatColors(threatData.threatLevel);

    const notificationId = await chrome.notifications.create({
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icons/icon128.png'),
      title: `${colors.icon} ${threatData.threatLevel} Security Alert`,
      message: `Potential threat detected: ${threatData.flags[0]?.detail || 'Suspicious activity'}`,
      priority: threatData.threatLevel === THREAT_LEVELS.CRITICAL ? 2 : 1,
      requireInteraction: threatData.threatLevel === THREAT_LEVELS.CRITICAL
    });

    return notificationId;
  } catch (error) {
    console.warn('[Security] Failed to show notification:', error);
    return null;
  }
}

/**
 * Log security alert to history
 * @async
 * @param {Object} alertData - Alert data to log
 */
async function logSecurityAlert(alertData) {
  if (!alertSettings?.logAlerts) return;

  try {
    const alert = {
      id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
      timestamp: Date.now(),
      url: alertData.url,
      threatLevel: alertData.threatLevel,
      threatScore: alertData.threatScore,
      recommendation: alertData.recommendation,
      flags: alertData.flags.slice(0, 5), // Limit flags stored
      type: alertData.type || 'url_threat'
    };

    // Add to history
    alertHistory.unshift(alert);

    // Limit history size
    if (alertHistory.length > (alertSettings.maxAlertHistory || 100)) {
      alertHistory = alertHistory.slice(0, alertSettings.maxAlertHistory || 100);
    }

    // Save to storage
    await chrome.storage.local.set({
      [SECURITY_STORAGE_KEYS.ALERTS]: alertHistory
    });

  } catch (error) {
    console.error('[Security] Failed to log alert:', error);
  }
}

/**
 * Get alert history
 * @param {number} [limit=50] - Maximum number of alerts to return
 * @returns {Array} Alert history
 */
function getAlertHistory(limit = 50) {
  return alertHistory.slice(0, limit);
}

/**
 * Clear alert history
 * @async
 */
async function clearAlertHistory() {
  alertHistory = [];
  await chrome.storage.local.set({
    [SECURITY_STORAGE_KEYS.ALERTS]: []
  });
}

/**
 * Get alert statistics
 * @returns {Object} Alert statistics
 */
function getAlertStats() {
  const now = Date.now();
  const dayAgo = now - 24 * 60 * 60 * 1000;
  const weekAgo = now - 7 * 24 * 60 * 60 * 1000;

  const stats = {
    total: alertHistory.length,
    last24Hours: 0,
    lastWeek: 0,
    byLevel: {
      [THREAT_LEVELS.CRITICAL]: 0,
      [THREAT_LEVELS.HIGH]: 0,
      [THREAT_LEVELS.MEDIUM]: 0,
      [THREAT_LEVELS.LOW]: 0
    }
  };

  for (const alert of alertHistory) {
    if (alert.timestamp > dayAgo) stats.last24Hours++;
    if (alert.timestamp > weekAgo) stats.lastWeek++;
    if (stats.byLevel[alert.threatLevel] !== undefined) {
      stats.byLevel[alert.threatLevel]++;
    }
  }

  return stats;
}

/**
 * Update alert settings
 * @param {Object} settings - New settings
 */
function updateAlertSettings(settings) {
  alertSettings = { ...alertSettings, ...settings };
}

/**
 * Get current alert settings
 * @returns {Object} Current settings
 */
function getAlertSettings() {
  return { ...alertSettings };
}

/**
 * Show threat warning to user via content script
 * @async
 * @param {number} tabId - Tab ID
 * @param {Object} threatData - Threat data
 */
async function showThreatWarning(tabId, threatData) {
  if (!alertSettings?.showOverlays) return;

  try {
    // Log the alert
    await logSecurityAlert(threatData);

    // Show notification
    await showChromeNotification(threatData);

    // Send message to content script to show overlay
    await chrome.tabs.sendMessage(tabId, {
      type: 'SECURITY_SHOW_WARNING',
      payload: {
        html: createWarningOverlay(threatData),
        threatData: threatData
      }
    });
  } catch (error) {
    console.warn('[Security] Failed to show threat warning:', error);
  }
}

// Export for use in other modules
if (typeof self !== 'undefined') {
  self.initAlertManager = initAlertManager;
  self.classifyThreatLevel = classifyThreatLevel;
  self.createWarningOverlay = createWarningOverlay;
  self.showChromeNotification = showChromeNotification;
  self.logSecurityAlert = logSecurityAlert;
  self.getAlertHistory = getAlertHistory;
  self.clearAlertHistory = clearAlertHistory;
  self.getAlertStats = getAlertStats;
  self.showThreatWarning = showThreatWarning;
  self.updateAlertSettings = updateAlertSettings;
  self.getAlertSettings = getAlertSettings;
  self.getThreatColors = getThreatColors;
}
