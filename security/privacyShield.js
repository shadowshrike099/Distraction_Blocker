/**
 * @fileoverview Privacy Shield Module
 * @description Provides tracker blocking and URL cleaning functionality
 * @version 1.0.0
 */

// Module state
let trackerDomains = null;
let trackingParams = null;
let privacySettings = null;
let trackerBloomFilter = null;
let privacyStats = {
  trackersBlocked: 0,
  urlsCleaned: 0,
  parametersCleaned: 0,
  lastReset: Date.now()
};

/**
 * Initialize the privacy shield with required data
 * @async
 * @returns {Promise<boolean>} Success status
 */
async function initPrivacyShield() {
  try {
    const [trackerData, paramsData] = await Promise.all([
      fetch(chrome.runtime.getURL('data/trackerDomains.json')).then(r => r.json()),
      fetch(chrome.runtime.getURL('data/trackingParams.json')).then(r => r.json())
    ]);

    trackerDomains = trackerData;
    trackingParams = paramsData;

    // Load saved settings or use defaults
    const stored = await chrome.storage.local.get([
      SECURITY_STORAGE_KEYS.SETTINGS,
      SECURITY_STORAGE_KEYS.TRACKER_STATS
    ]);

    privacySettings = stored[SECURITY_STORAGE_KEYS.SETTINGS]?.privacy || DEFAULT_PRIVACY_SETTINGS;

    if (stored[SECURITY_STORAGE_KEYS.TRACKER_STATS]) {
      privacyStats = stored[SECURITY_STORAGE_KEYS.TRACKER_STATS];
    }

    // Initialize Bloom filter for fast tracker lookup
    initTrackerBloomFilter();

    console.log('[Security] Privacy Shield initialized successfully');
    return true;
  } catch (error) {
    console.error('[Security] Failed to initialize Privacy Shield:', error);
    return false;
  }
}

/**
 * Initialize Bloom filter with tracker domains
 * @private
 */
function initTrackerBloomFilter() {
  if (!trackerDomains) return;

  // Count total domains
  let totalDomains = 0;
  for (const category of Object.keys(trackerDomains)) {
    if (Array.isArray(trackerDomains[category])) {
      totalDomains += trackerDomains[category].length;
    }
  }

  // Create optimally sized Bloom filter
  trackerBloomFilter = BloomFilter.createOptimal(totalDomains, 0.01);

  // Add all tracker domains
  for (const category of Object.keys(trackerDomains)) {
    if (Array.isArray(trackerDomains[category])) {
      for (const domain of trackerDomains[category]) {
        trackerBloomFilter.add(domain.toLowerCase());
      }
    }
  }
}

/**
 * Check if domain is a known tracker
 * @param {string} domain - Domain to check
 * @returns {Object} Tracker check result
 */
function isTrackerDomain(domain) {
  const result = {
    isTracker: false,
    categories: [],
    shouldBlock: false
  };

  if (!trackerDomains || !domain || !privacySettings?.blockTrackers) {
    return result;
  }

  const domainLower = domain.toLowerCase();

  // Quick check with Bloom filter first
  if (trackerBloomFilter && !trackerBloomFilter.contains(domainLower)) {
    // Definitely not in the set, but also check subdomain matches
    const parts = domainLower.split('.');
    let found = false;
    for (let i = 1; i < parts.length; i++) {
      const parentDomain = parts.slice(i).join('.');
      if (trackerBloomFilter.contains(parentDomain)) {
        found = true;
        break;
      }
    }
    if (!found) return result;
  }

  // Detailed check against each category
  for (const [category, domains] of Object.entries(trackerDomains)) {
    if (!Array.isArray(domains)) continue;
    if (!privacySettings.trackerCategories?.[category]) continue;

    for (const trackerDomain of domains) {
      if (domainLower === trackerDomain || domainLower.endsWith('.' + trackerDomain)) {
        result.isTracker = true;
        result.categories.push(category);
        break;
      }
    }
  }

  if (result.categories.length > 0) {
    result.shouldBlock = result.categories.some(cat =>
      privacySettings.trackerCategories?.[cat] === true
    );
  }

  return result;
}

/**
 * Clean tracking parameters from URL
 * @param {string} url - URL to clean
 * @returns {Object} URL cleaning result
 */
function cleanUrl(url) {
  const result = {
    modified: false,
    originalUrl: url,
    cleanedUrl: url,
    removedParams: [],
    preservedParams: []
  };

  if (!trackingParams || !url || !privacySettings?.cleanUrls) {
    return result;
  }

  try {
    const urlObj = new URL(url);

    // Check if domain should be preserved
    for (const preserveDomain of trackingParams.preserveDomains || []) {
      if (urlObj.hostname.includes(preserveDomain)) {
        return result;
      }
    }

    // Get all parameters
    const paramsToRemove = [];

    for (const [key, value] of urlObj.searchParams) {
      // Check if this is a tracking parameter
      if (trackingParams.parameters.includes(key)) {
        // Make sure it's not a preserved parameter
        if (!trackingParams.preserveParams.includes(key)) {
          paramsToRemove.push(key);
        } else {
          result.preservedParams.push(key);
        }
      }
    }

    // Remove tracking parameters
    for (const param of paramsToRemove) {
      urlObj.searchParams.delete(param);
      result.removedParams.push(param);
    }

    if (result.removedParams.length > 0) {
      result.modified = true;
      result.cleanedUrl = urlObj.toString();

      // Update stats
      privacyStats.urlsCleaned++;
      privacyStats.parametersCleaned += result.removedParams.length;
      savePrivacyStats();
    }

  } catch (error) {
    console.warn('[Security] URL cleaning error:', error);
  }

  return result;
}

/**
 * Generate declarativeNetRequest rules for tracker blocking
 * @returns {Array} Array of DNR rules
 */
function getTrackerBlockingRules() {
  const rules = [];
  let ruleId = 5000; // Start with high ID to avoid conflicts

  if (!trackerDomains || !privacySettings?.blockTrackers) {
    return rules;
  }

  for (const [category, domains] of Object.entries(trackerDomains)) {
    if (!Array.isArray(domains)) continue;
    if (!privacySettings.trackerCategories?.[category]) continue;

    for (const domain of domains) {
      rules.push({
        id: ruleId++,
        priority: 1,
        action: { type: 'block' },
        condition: {
          urlFilter: `||${domain}^`,
          resourceTypes: ['script', 'image', 'xmlhttprequest', 'sub_frame', 'ping']
        }
      });

      // Limit rules to prevent performance issues
      if (ruleId > 6000) break;
    }
    if (ruleId > 6000) break;
  }

  return rules;
}

/**
 * Update tracker blocking rules with Chrome
 * @async
 * @param {Object} categories - Categories to enable/disable
 * @returns {Promise<boolean>} Success status
 */
async function updateBlockingRules(categories) {
  try {
    // Update settings
    privacySettings.trackerCategories = { ...privacySettings.trackerCategories, ...categories };

    // Save settings
    const currentSettings = await chrome.storage.local.get(SECURITY_STORAGE_KEYS.SETTINGS);
    await chrome.storage.local.set({
      [SECURITY_STORAGE_KEYS.SETTINGS]: {
        ...currentSettings[SECURITY_STORAGE_KEYS.SETTINGS],
        privacy: privacySettings
      }
    });

    // Get new rules
    const newRules = getTrackerBlockingRules();

    // Get existing security rules (IDs 5000+)
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const securityRuleIds = existingRules
      .filter(r => r.id >= 5000)
      .map(r => r.id);

    // Update rules
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: securityRuleIds,
      addRules: newRules
    });

    console.log(`[Security] Updated ${newRules.length} tracker blocking rules`);
    return true;
  } catch (error) {
    console.error('[Security] Failed to update blocking rules:', error);
    return false;
  }
}

/**
 * Save privacy statistics to storage
 * @async
 * @private
 */
async function savePrivacyStats() {
  try {
    await chrome.storage.local.set({
      [SECURITY_STORAGE_KEYS.TRACKER_STATS]: privacyStats
    });
  } catch (error) {
    console.warn('[Security] Failed to save privacy stats:', error);
  }
}

/**
 * Get current privacy statistics
 * @returns {Object} Privacy statistics
 */
function getPrivacyStats() {
  return {
    ...privacyStats,
    settings: { ...privacySettings }
  };
}

/**
 * Record a blocked tracker
 * @param {string} domain - Blocked domain
 * @param {string} category - Tracker category
 */
function recordBlockedTracker(domain, category) {
  privacyStats.trackersBlocked++;
  savePrivacyStats();
}

/**
 * Reset privacy statistics
 * @async
 */
async function resetPrivacyStats() {
  privacyStats = {
    trackersBlocked: 0,
    urlsCleaned: 0,
    parametersCleaned: 0,
    lastReset: Date.now()
  };
  await savePrivacyStats();
}

/**
 * Update privacy settings
 * @param {Object} settings - New settings
 */
function updatePrivacySettings(settings) {
  privacySettings = { ...privacySettings, ...settings };
}

/**
 * Get current privacy settings
 * @returns {Object} Current settings
 */
function getPrivacySettings() {
  return { ...privacySettings };
}

/**
 * Clean tracking parameters from URL (for webNavigation)
 * @param {string} url - URL to clean
 * @returns {Object} Result with modified flag and cleanedUrl
 */
function cleanTrackingParams(url) {
  return cleanUrl(url);
}

// Export for use in other modules
if (typeof self !== 'undefined') {
  self.initPrivacyShield = initPrivacyShield;
  self.cleanUrl = cleanUrl;
  self.cleanTrackingParams = cleanTrackingParams;
  self.isTrackerDomain = isTrackerDomain;
  self.getTrackerBlockingRules = getTrackerBlockingRules;
  self.updateBlockingRules = updateBlockingRules;
  self.getPrivacyStats = getPrivacyStats;
  self.recordBlockedTracker = recordBlockedTracker;
  self.resetPrivacyStats = resetPrivacyStats;
  self.updatePrivacySettings = updatePrivacySettings;
  self.getPrivacySettings = getPrivacySettings;
}
