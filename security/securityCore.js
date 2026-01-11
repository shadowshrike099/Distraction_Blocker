/**
 * @fileoverview Security Core Module
 * @description Main coordinator for all security modules
 * @version 1.0.0
 */

// Module state
let securityInitialized = false;
let securityWhitelist = [];
let securityStats = {
  urlsAnalyzed: 0,
  threatsBlocked: 0,
  phishingDetected: 0,
  contentBlocked: 0,
  lastUpdated: Date.now()
};

/**
 * Initialize all security modules
 * @async
 * @returns {Promise<boolean>} Success status
 */
async function initializeSecurity() {
  if (securityInitialized) {
    console.log('[Security] Already initialized');
    return true;
  }

  try {
    console.log('[Security] Initializing security modules...');

    // Load whitelist and stats from storage
    const stored = await chrome.storage.local.get([
      SECURITY_STORAGE_KEYS.WHITELIST,
      SECURITY_STORAGE_KEYS.STATS
    ]);

    securityWhitelist = stored[SECURITY_STORAGE_KEYS.WHITELIST] || [];
    if (stored[SECURITY_STORAGE_KEYS.STATS]) {
      securityStats = stored[SECURITY_STORAGE_KEYS.STATS];
    }

    // Initialize all modules in parallel
    const results = await Promise.all([
      initUrlAnalyzer(),
      initPhishingDetector(),
      initContentFilter(),
      initPrivacyShield(),
      initAlertManager()
    ]);

    const allSuccess = results.every(r => r === true);

    if (allSuccess) {
      securityInitialized = true;
      console.log('[Security] All security modules initialized successfully');

      // Set up tracker blocking rules
      await updateBlockingRules({});
    } else {
      console.warn('[Security] Some modules failed to initialize');
    }

    return allSuccess;
  } catch (error) {
    console.error('[Security] Initialization failed:', error);
    return false;
  }
}

/**
 * Check if domain is whitelisted
 * @param {string} domain - Domain to check
 * @returns {boolean} Whether domain is whitelisted
 */
function isWhitelisted(domain) {
  if (!domain) return false;

  const domainLower = domain.toLowerCase();

  return securityWhitelist.some(whitelisted => {
    if (whitelisted.startsWith('*.')) {
      // Wildcard match
      const baseDomain = whitelisted.slice(2);
      return domainLower === baseDomain || domainLower.endsWith('.' + baseDomain);
    }
    return domainLower === whitelisted || domainLower.endsWith('.' + whitelisted);
  });
}

/**
 * Add domain to whitelist
 * @async
 * @param {string} domain - Domain to add
 * @returns {Promise<boolean>} Success status
 */
async function addToWhitelist(domain) {
  try {
    const domainLower = domain.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];

    if (!securityWhitelist.includes(domainLower)) {
      securityWhitelist.push(domainLower);

      await chrome.storage.local.set({
        [SECURITY_STORAGE_KEYS.WHITELIST]: securityWhitelist
      });
    }

    return true;
  } catch (error) {
    console.error('[Security] Failed to add to whitelist:', error);
    return false;
  }
}

/**
 * Remove domain from whitelist
 * @async
 * @param {string} domain - Domain to remove
 * @returns {Promise<boolean>} Success status
 */
async function removeFromWhitelist(domain) {
  try {
    const domainLower = domain.toLowerCase();
    const index = securityWhitelist.indexOf(domainLower);

    if (index !== -1) {
      securityWhitelist.splice(index, 1);

      await chrome.storage.local.set({
        [SECURITY_STORAGE_KEYS.WHITELIST]: securityWhitelist
      });
    }

    return true;
  } catch (error) {
    console.error('[Security] Failed to remove from whitelist:', error);
    return false;
  }
}

/**
 * Get current whitelist
 * @returns {Array<string>} Whitelist domains
 */
function getWhitelist() {
  return [...securityWhitelist];
}

/**
 * Coordinate all URL security analysis modules
 * @async
 * @param {string} url - URL to analyze
 * @returns {Promise<Object>} Combined security analysis result
 */
async function analyzeUrlSecurity(url) {
  const result = {
    url: url,
    isWhitelisted: false,
    threatScore: 0,
    threatLevel: THREAT_LEVELS.NONE,
    recommendation: RECOMMENDATIONS.ALLOW,
    flags: [],
    analysis: {
      url: null,
      content: null,
      privacy: null
    },
    timestamp: Date.now()
  };

  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;

    // Check whitelist first
    if (isWhitelisted(domain)) {
      result.isWhitelisted = true;
      return result;
    }

    // Update stats
    securityStats.urlsAnalyzed++;

    // Run URL analysis
    if (typeof analyzeUrl === 'function') {
      result.analysis.url = await analyzeUrl(url);

      if (result.analysis.url) {
        result.flags.push(...result.analysis.url.flags);
        result.threatScore = Math.max(result.threatScore, result.analysis.url.threatScore);
      }
    }

    // Run content filter check
    if (typeof checkUrl === 'function') {
      result.analysis.content = checkUrl(url);

      if (result.analysis.content?.isBlocked) {
        result.flags.push({
          type: 'content_blocked',
          detail: result.analysis.content.reason,
          score: result.analysis.content.score
        });
        result.threatScore = Math.max(result.threatScore, result.analysis.content.score);
      }
    }

    // Check for trackers
    if (typeof isTrackerDomain === 'function') {
      result.analysis.privacy = isTrackerDomain(domain);

      if (result.analysis.privacy?.isTracker) {
        result.flags.push({
          type: 'tracker_detected',
          detail: `Tracker categories: ${result.analysis.privacy.categories.join(', ')}`,
          score: 10
        });
      }
    }

    // Determine final threat level and recommendation
    result.threatLevel = classifyThreatLevel(result.threatScore);

    if (result.threatScore >= THREAT_THRESHOLDS.HIGH) {
      result.recommendation = RECOMMENDATIONS.BLOCK;
      securityStats.threatsBlocked++;
    } else if (result.threatScore >= THREAT_THRESHOLDS.MEDIUM) {
      result.recommendation = RECOMMENDATIONS.WARN;
    }

    // Save stats periodically
    if (securityStats.urlsAnalyzed % 10 === 0) {
      await saveSecurityStats();
    }

  } catch (error) {
    console.error('[Security] URL security analysis error:', error);
  }

  return result;
}

/**
 * Coordinate page security analysis
 * @async
 * @param {Object} pageData - Page data from content script
 * @returns {Promise<Object>} Combined page security analysis
 */
async function analyzePageSecurity(pageData) {
  const result = {
    url: pageData.url,
    isWhitelisted: false,
    isPhishing: false,
    threatScore: 0,
    threatLevel: THREAT_LEVELS.NONE,
    recommendation: RECOMMENDATIONS.ALLOW,
    flags: [],
    analysis: {
      phishing: null,
      content: null
    },
    timestamp: Date.now()
  };

  try {
    let domain = '';
    try {
      domain = new URL(pageData.url).hostname;
    } catch (e) {
      domain = pageData.domain || '';
    }

    // Check whitelist
    if (isWhitelisted(domain)) {
      result.isWhitelisted = true;
      return result;
    }

    // Run phishing analysis
    if (typeof analyzePage === 'function') {
      result.analysis.phishing = await analyzePage(pageData);

      if (result.analysis.phishing) {
        result.isPhishing = result.analysis.phishing.isPhishing;
        result.flags.push(...result.analysis.phishing.flags);
        result.threatScore = Math.max(result.threatScore, result.analysis.phishing.threatScore);

        if (result.isPhishing) {
          securityStats.phishingDetected++;
        }
      }
    }

    // Run content analysis
    if (typeof analyzePageContent === 'function') {
      result.analysis.content = analyzePageContent(pageData);

      if (result.analysis.content?.shouldBlock) {
        result.flags.push({
          type: 'content_violation',
          detail: `Blocked categories: ${result.analysis.content.matchedCategories.join(', ')}`,
          score: result.analysis.content.score
        });
        result.threatScore = Math.max(result.threatScore, result.analysis.content.score);
        securityStats.contentBlocked++;
      }
    }

    // Determine final threat level and recommendation
    result.threatLevel = classifyThreatLevel(result.threatScore);

    if (result.threatScore >= THREAT_THRESHOLDS.HIGH) {
      result.recommendation = RECOMMENDATIONS.BLOCK;
    } else if (result.threatScore >= THREAT_THRESHOLDS.MEDIUM) {
      result.recommendation = RECOMMENDATIONS.WARN;
    }

  } catch (error) {
    console.error('[Security] Page security analysis error:', error);
  }

  return result;
}

/**
 * Save security statistics to storage
 * @async
 */
async function saveSecurityStats() {
  try {
    securityStats.lastUpdated = Date.now();
    await chrome.storage.local.set({
      [SECURITY_STORAGE_KEYS.STATS]: securityStats
    });
  } catch (error) {
    console.warn('[Security] Failed to save stats:', error);
  }
}

/**
 * Get aggregated security statistics
 * @async
 * @returns {Promise<Object>} Combined statistics from all modules
 */
async function getSecurityStats() {
  const alertStats = typeof getAlertStats === 'function' ? getAlertStats() : {};
  const privacyStats = typeof getPrivacyStats === 'function' ? getPrivacyStats() : {};

  return {
    core: { ...securityStats },
    alerts: alertStats,
    privacy: privacyStats,
    whitelist: {
      count: securityWhitelist.length,
      domains: securityWhitelist.slice(0, 10) // Return first 10 for preview
    }
  };
}

/**
 * Get current security settings from all modules
 * @async
 * @returns {Promise<Object>} Combined settings
 */
async function getSecuritySettings() {
  const stored = await chrome.storage.local.get(SECURITY_STORAGE_KEYS.SETTINGS);

  return {
    features: stored[SECURITY_STORAGE_KEYS.SETTINGS]?.features || SECURITY_FEATURES,
    thresholds: THREAT_THRESHOLDS,
    contentCategories: typeof getContentFilterSettings === 'function'
      ? getContentFilterSettings()
      : DEFAULT_CONTENT_SETTINGS,
    privacy: typeof getPrivacySettings === 'function'
      ? getPrivacySettings()
      : DEFAULT_PRIVACY_SETTINGS,
    alerts: typeof getAlertSettings === 'function'
      ? getAlertSettings()
      : DEFAULT_ALERT_SETTINGS
  };
}

/**
 * Update security settings across all modules
 * @async
 * @param {Object} settings - Settings to update
 * @returns {Promise<boolean>} Success status
 */
async function updateSecuritySettings(settings) {
  try {
    const currentSettings = await chrome.storage.local.get(SECURITY_STORAGE_KEYS.SETTINGS);
    const merged = {
      ...currentSettings[SECURITY_STORAGE_KEYS.SETTINGS],
      ...settings
    };

    // Update individual module settings
    if (settings.contentCategories && typeof updateContentFilterSettings === 'function') {
      updateContentFilterSettings(settings.contentCategories);
    }

    if (settings.privacy && typeof updatePrivacySettings === 'function') {
      updatePrivacySettings(settings.privacy);
      // Update tracker blocking rules
      if (settings.privacy.trackerCategories) {
        await updateBlockingRules(settings.privacy.trackerCategories);
      }
    }

    if (settings.alerts && typeof updateAlertSettings === 'function') {
      updateAlertSettings(settings.alerts);
    }

    // Save to storage
    await chrome.storage.local.set({
      [SECURITY_STORAGE_KEYS.SETTINGS]: merged
    });

    console.log('[Security] Settings updated successfully');
    return true;
  } catch (error) {
    console.error('[Security] Failed to update settings:', error);
    return false;
  }
}

/**
 * Reset all security statistics
 * @async
 */
async function resetSecurityStats() {
  securityStats = {
    urlsAnalyzed: 0,
    threatsBlocked: 0,
    phishingDetected: 0,
    contentBlocked: 0,
    lastUpdated: Date.now()
  };

  await saveSecurityStats();

  if (typeof resetPrivacyStats === 'function') {
    await resetPrivacyStats();
  }

  if (typeof clearAlertHistory === 'function') {
    await clearAlertHistory();
  }
}

/**
 * Export security data for backup
 * @async
 * @returns {Promise<Object>} Exportable security data
 */
async function exportSecurityData() {
  const stats = await getSecurityStats();
  const settings = await getSecuritySettings();
  const alerts = typeof getAlertHistory === 'function' ? getAlertHistory(100) : [];

  return {
    exportDate: new Date().toISOString(),
    version: '1.0.0',
    stats: stats,
    settings: settings,
    whitelist: securityWhitelist,
    alertHistory: alerts
  };
}

/**
 * Import security data from backup
 * @async
 * @param {Object} data - Data to import
 * @returns {Promise<boolean>} Success status
 */
async function importSecurityData(data) {
  try {
    if (data.whitelist && Array.isArray(data.whitelist)) {
      securityWhitelist = data.whitelist;
      await chrome.storage.local.set({
        [SECURITY_STORAGE_KEYS.WHITELIST]: securityWhitelist
      });
    }

    if (data.settings) {
      await updateSecuritySettings(data.settings);
    }

    console.log('[Security] Data imported successfully');
    return true;
  } catch (error) {
    console.error('[Security] Failed to import data:', error);
    return false;
  }
}

// Export for use in other modules
if (typeof self !== 'undefined') {
  self.initializeSecurity = initializeSecurity;
  self.analyzeUrlSecurity = analyzeUrlSecurity;
  self.analyzePageSecurity = analyzePageSecurity;
  self.getSecurityStats = getSecurityStats;
  self.getSecuritySettings = getSecuritySettings;
  self.updateSecuritySettings = updateSecuritySettings;
  self.addToWhitelist = addToWhitelist;
  self.removeFromWhitelist = removeFromWhitelist;
  self.getWhitelist = getWhitelist;
  self.isWhitelisted = isWhitelisted;
  self.resetSecurityStats = resetSecurityStats;
  self.exportSecurityData = exportSecurityData;
  self.importSecurityData = importSecurityData;
}
