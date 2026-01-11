/**
 * @fileoverview Security Center UI Controller
 * @description Manages the Security Center tab in the options page
 * @version 1.0.0
 */

// Wait for DOM to be ready
document.addEventListener('DOMContentLoaded', initSecurityCenter);

/**
 * Initialize the Security Center
 */
async function initSecurityCenter() {
  // Load and display security stats
  await loadSecurityStats();

  // Load current settings
  await loadSecuritySettings();

  // Load whitelist
  await loadWhitelist();

  // Load alert history
  await loadAlertHistory();

  // Set up event listeners
  setupSecurityEventListeners();
}

/**
 * Load and display security statistics
 */
async function loadSecurityStats() {
  try {
    const response = await sendSecurityMessage('SECURITY_GET_STATS');

    if (response && response.core) {
      document.getElementById('threats-blocked-count').textContent =
        response.core.threatsBlocked || 0;
      document.getElementById('urls-analyzed-count').textContent =
        response.core.urlsAnalyzed || 0;
      document.getElementById('phishing-blocked-count').textContent =
        response.core.phishingDetected || 0;
      document.getElementById('trackers-blocked-count').textContent =
        response.privacy?.trackersBlocked || 0;
    }
  } catch (error) {
    console.warn('[Security Center] Failed to load stats:', error);
  }
}

/**
 * Load current security settings
 */
async function loadSecuritySettings() {
  try {
    const response = await sendSecurityMessage('SECURITY_GET_SETTINGS');

    if (response && !response.error) {
      // Feature toggles
      if (response.features) {
        setToggle('toggle-url-analysis', response.features.urlAnalysis);
        setToggle('toggle-phishing-detection', response.features.phishingDetection);
        setToggle('toggle-content-filtering', response.features.contentFiltering);
        setToggle('toggle-privacy-protection', response.features.privacyProtection);
      }

      // Content categories
      if (response.contentCategories) {
        setToggle('filter-adult', response.contentCategories.adult?.enabled);
        setToggle('filter-gambling', response.contentCategories.gambling?.enabled);
        setToggle('filter-violence', response.contentCategories.violence?.enabled);
        setToggle('filter-drugs', response.contentCategories.drugs?.enabled);
        setToggle('filter-piracy', response.contentCategories.piracy?.enabled);
      }

      // Privacy settings
      if (response.privacy) {
        setToggle('clean-urls', response.privacy.cleanUrls);
        if (response.privacy.trackerCategories) {
          setToggle('block-analytics', response.privacy.trackerCategories.analytics);
          setToggle('block-advertising', response.privacy.trackerCategories.advertising);
          setToggle('block-social', response.privacy.trackerCategories.social);
          setToggle('block-fingerprinting', response.privacy.trackerCategories.fingerprinting);
        }
      }
    }
  } catch (error) {
    console.warn('[Security Center] Failed to load settings:', error);
  }
}

/**
 * Set toggle checkbox state
 * @param {string} id - Element ID
 * @param {boolean} checked - Whether checked
 */
function setToggle(id, checked) {
  const toggle = document.getElementById(id);
  if (toggle) {
    toggle.checked = checked !== false;
  }
}

/**
 * Load whitelist
 */
async function loadWhitelist() {
  try {
    const response = await sendSecurityMessage('SECURITY_GET_WHITELIST');

    const container = document.getElementById('whitelist-container');
    container.innerHTML = '';

    if (response && response.success && response.whitelist) {
      if (response.whitelist.length === 0) {
        container.innerHTML = '<li class="empty-state">No trusted sites added</li>';
      } else {
        response.whitelist.forEach(domain => {
          const li = document.createElement('li');
          li.innerHTML = `
            <span>${escapeHtml(domain)}</span>
            <button class="remove-btn" data-domain="${escapeHtml(domain)}">Remove</button>
          `;
          container.appendChild(li);
        });
      }
    }
  } catch (error) {
    console.warn('[Security Center] Failed to load whitelist:', error);
  }
}

/**
 * Load alert history
 */
async function loadAlertHistory() {
  try {
    const response = await sendSecurityMessage('SECURITY_GET_ALERTS');

    const container = document.getElementById('alerts-container');
    container.innerHTML = '';

    if (response && response.success && response.alerts) {
      if (response.alerts.length === 0) {
        container.innerHTML = '<div class="empty-state">No security alerts recorded</div>';
      } else {
        response.alerts.slice(0, 50).forEach(alert => {
          const div = document.createElement('div');
          div.className = `alert-item ${alert.threatLevel}`;

          const icon = getAlertIcon(alert.threatLevel);
          const time = formatTimeAgo(alert.timestamp);
          const url = alert.url ? truncateUrl(alert.url, 50) : 'Unknown';

          div.innerHTML = `
            <span class="alert-icon">${icon}</span>
            <div class="alert-content">
              <div class="alert-title">${alert.threatLevel} - Score: ${alert.threatScore || 0}</div>
              <div class="alert-url">${escapeHtml(url)}</div>
            </div>
            <span class="alert-time">${time}</span>
          `;
          container.appendChild(div);
        });
      }
    }
  } catch (error) {
    console.warn('[Security Center] Failed to load alerts:', error);
  }
}

/**
 * Get icon for alert level
 * @param {string} level - Threat level
 * @returns {string} Icon emoji
 */
function getAlertIcon(level) {
  const icons = {
    CRITICAL: '🚨',
    HIGH: '⚠️',
    MEDIUM: '⚡',
    LOW: 'ℹ️'
  };
  return icons[level] || '🔔';
}

/**
 * Format timestamp as relative time
 * @param {number} timestamp - Unix timestamp
 * @returns {string} Relative time string
 */
function formatTimeAgo(timestamp) {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);

  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
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
 * Set up event listeners for Security Center
 */
function setupSecurityEventListeners() {
  // Feature toggles
  const featureToggles = [
    'toggle-url-analysis',
    'toggle-phishing-detection',
    'toggle-content-filtering',
    'toggle-privacy-protection'
  ];

  featureToggles.forEach(id => {
    const toggle = document.getElementById(id);
    if (toggle) {
      toggle.addEventListener('change', () => saveFeatureSettings());
    }
  });

  // Category toggles
  const categoryToggles = [
    'filter-adult',
    'filter-gambling',
    'filter-violence',
    'filter-drugs',
    'filter-piracy'
  ];

  categoryToggles.forEach(id => {
    const toggle = document.getElementById(id);
    if (toggle) {
      toggle.addEventListener('change', () => saveCategorySettings());
    }
  });

  // Privacy toggles
  const privacyToggles = [
    'clean-urls',
    'block-analytics',
    'block-advertising',
    'block-social',
    'block-fingerprinting'
  ];

  privacyToggles.forEach(id => {
    const toggle = document.getElementById(id);
    if (toggle) {
      toggle.addEventListener('change', () => savePrivacySettings());
    }
  });

  // Whitelist add
  const addWhitelistBtn = document.getElementById('add-whitelist');
  if (addWhitelistBtn) {
    addWhitelistBtn.addEventListener('click', addToWhitelist);
  }

  const whitelistInput = document.getElementById('whitelist-input');
  if (whitelistInput) {
    whitelistInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') addToWhitelist();
    });
  }

  // Whitelist remove
  const whitelistContainer = document.getElementById('whitelist-container');
  if (whitelistContainer) {
    whitelistContainer.addEventListener('click', (e) => {
      if (e.target.classList.contains('remove-btn')) {
        removeFromWhitelist(e.target.dataset.domain);
      }
    });
  }

  // Alert buttons
  const refreshAlertsBtn = document.getElementById('refresh-alerts');
  if (refreshAlertsBtn) {
    refreshAlertsBtn.addEventListener('click', loadAlertHistory);
  }

  const clearAlertsBtn = document.getElementById('clear-alerts');
  if (clearAlertsBtn) {
    clearAlertsBtn.addEventListener('click', clearAlerts);
  }

  // Export buttons
  const exportJsonBtn = document.getElementById('export-security-json');
  if (exportJsonBtn) {
    exportJsonBtn.addEventListener('click', exportSecurityDataJSON);
  }

  const exportAlertsCsvBtn = document.getElementById('export-alerts-csv');
  if (exportAlertsCsvBtn) {
    exportAlertsCsvBtn.addEventListener('click', exportAlertsCSV);
  }
}

/**
 * Save feature toggle settings
 */
async function saveFeatureSettings() {
  const features = {
    urlAnalysis: document.getElementById('toggle-url-analysis')?.checked,
    phishingDetection: document.getElementById('toggle-phishing-detection')?.checked,
    contentFiltering: document.getElementById('toggle-content-filtering')?.checked,
    privacyProtection: document.getElementById('toggle-privacy-protection')?.checked
  };

  await sendSecurityMessage('SECURITY_UPDATE_SETTINGS', { features });
}

/**
 * Save category filter settings
 */
async function saveCategorySettings() {
  const contentCategories = {
    adult: { enabled: document.getElementById('filter-adult')?.checked },
    gambling: { enabled: document.getElementById('filter-gambling')?.checked },
    violence: { enabled: document.getElementById('filter-violence')?.checked },
    drugs: { enabled: document.getElementById('filter-drugs')?.checked },
    piracy: { enabled: document.getElementById('filter-piracy')?.checked }
  };

  await sendSecurityMessage('SECURITY_UPDATE_SETTINGS', { contentCategories });
}

/**
 * Save privacy settings
 */
async function savePrivacySettings() {
  const privacy = {
    cleanUrls: document.getElementById('clean-urls')?.checked,
    trackerCategories: {
      analytics: document.getElementById('block-analytics')?.checked,
      advertising: document.getElementById('block-advertising')?.checked,
      social: document.getElementById('block-social')?.checked,
      fingerprinting: document.getElementById('block-fingerprinting')?.checked
    }
  };

  await sendSecurityMessage('SECURITY_UPDATE_SETTINGS', { privacy });
}

/**
 * Add domain to whitelist
 */
async function addToWhitelist() {
  const input = document.getElementById('whitelist-input');
  const domain = input.value.trim().toLowerCase();

  if (!domain) return;

  // Basic domain validation
  if (!domain.includes('.') || domain.includes(' ')) {
    alert('Please enter a valid domain');
    return;
  }

  const response = await sendSecurityMessage('SECURITY_WHITELIST_ADD', { domain });

  if (response && response.success) {
    input.value = '';
    await loadWhitelist();
  } else {
    alert('Failed to add domain to whitelist');
  }
}

/**
 * Remove domain from whitelist
 * @param {string} domain - Domain to remove
 */
async function removeFromWhitelist(domain) {
  const response = await sendSecurityMessage('SECURITY_WHITELIST_REMOVE', { domain });

  if (response && response.success) {
    await loadWhitelist();
  } else {
    alert('Failed to remove domain from whitelist');
  }
}

/**
 * Clear all alerts
 */
async function clearAlerts() {
  if (!confirm('Clear all security alerts?')) return;

  const response = await sendSecurityMessage('SECURITY_CLEAR_ALERTS');

  if (response && response.success) {
    await loadAlertHistory();
  }
}

/**
 * Export all security data as JSON
 */
async function exportSecurityDataJSON() {
  const response = await sendSecurityMessage('SECURITY_EXPORT_DATA');

  if (response && !response.error) {
    const jsonContent = JSON.stringify(response, null, 2);
    downloadFile(
      jsonContent,
      `security-data-${new Date().toISOString().split('T')[0]}.json`,
      'application/json'
    );
  } else {
    alert('Failed to export security data');
  }
}

/**
 * Export alerts as CSV
 */
async function exportAlertsCSV() {
  const response = await sendSecurityMessage('SECURITY_GET_ALERTS');

  if (response && response.success && response.alerts) {
    const headers = ['timestamp', 'threatLevel', 'threatScore', 'url', 'recommendation'];
    let csvContent = headers.join(',') + '\n';

    response.alerts.forEach(alert => {
      const row = headers.map(h => {
        let value = alert[h] || '';
        if (h === 'timestamp') {
          value = new Date(value).toISOString();
        }
        const strValue = String(value);
        if (strValue.includes(',') || strValue.includes('"')) {
          return '"' + strValue.replace(/"/g, '""') + '"';
        }
        return strValue;
      });
      csvContent += row.join(',') + '\n';
    });

    downloadFile(
      csvContent,
      `security-alerts-${new Date().toISOString().split('T')[0]}.csv`,
      'text/csv'
    );
  } else {
    alert('Failed to export alerts');
  }
}

/**
 * Download file helper
 * @param {string} content - File content
 * @param {string} filename - File name
 * @param {string} mimeType - MIME type
 */
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

/**
 * Send message to background script
 * @param {string} type - Message type
 * @param {Object} payload - Message payload
 * @returns {Promise<any>} Response
 */
function sendSecurityMessage(type, payload = {}) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type, payload }, (response) => {
      if (chrome.runtime.lastError) {
        console.warn('[Security Center] Message error:', chrome.runtime.lastError);
        resolve(null);
      } else {
        resolve(response);
      }
    });
  });
}
