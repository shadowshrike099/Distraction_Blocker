/**
 * @fileoverview Content Category Filtering Module
 * @description Filters content based on categories like adult, gambling, violence, etc.
 * @version 1.0.0
 */

// Module state
let adultKeywords = null;
let contentFilterSettings = null;
let contentFilterCache = new Map();

/**
 * Initialize the content filter with required data
 * @async
 * @returns {Promise<boolean>} Success status
 */
async function initContentFilter() {
  try {
    adultKeywords = await fetch(chrome.runtime.getURL('data/adultKeywords.json')).then(r => r.json());

    // Load saved settings or use defaults
    const stored = await chrome.storage.local.get(SECURITY_STORAGE_KEYS.SETTINGS);
    contentFilterSettings = stored[SECURITY_STORAGE_KEYS.SETTINGS]?.contentCategories || DEFAULT_CONTENT_SETTINGS;

    // Ensure adult filtering is enabled by default if not set
    if (!contentFilterSettings.adult) {
      contentFilterSettings.adult = { enabled: true, strictness: 'high' };
    }

    console.log('[Security] Content Filter initialized with settings:', JSON.stringify(contentFilterSettings));
    return true;
  } catch (error) {
    console.error('[Security] Failed to initialize Content Filter:', error);
    // Use hardcoded defaults as fallback
    contentFilterSettings = {
      adult: { enabled: true, strictness: 'high' },
      gambling: { enabled: false, strictness: 'medium' },
      violence: { enabled: false, strictness: 'medium' },
      drugs: { enabled: false, strictness: 'low' },
      piracy: { enabled: false, strictness: 'low' }
    };
    return true; // Return true so other modules can still work
  }
}

/**
 * Update content filter settings
 * @param {Object} settings - New settings
 */
function updateContentFilterSettings(settings) {
  contentFilterSettings = { ...contentFilterSettings, ...settings };
}

/**
 * Check if domain is in blocklist for any category
 * @param {string} domain - Domain to check
 * @returns {Object} Blocklist check result
 */
function checkDomainBlocklist(domain) {
  const result = {
    isBlocked: false,
    categories: [],
    score: 0
  };

  if (!adultKeywords || !domain || !contentFilterSettings) {
    return result;
  }

  const domainLower = domain.toLowerCase();

  // Check adult TLDs
  if (contentFilterSettings.adult?.enabled) {
    for (const tld of adultKeywords.categories.adult.blockTlds || []) {
      if (domainLower.endsWith(tld)) {
        result.isBlocked = true;
        result.categories.push('adult');
        result.score += 100;
        return result; // Immediate block
      }
    }
  }

  // Check gambling TLDs
  if (contentFilterSettings.gambling?.enabled) {
    for (const tld of adultKeywords.categories.gambling.blockTlds || []) {
      if (domainLower.endsWith(tld)) {
        result.isBlocked = true;
        result.categories.push('gambling');
        result.score += 100;
        return result;
      }
    }
  }

  return result;
}

/**
 * Analyze URL keywords for content categories
 * @param {string} url - URL to analyze
 * @returns {Object} Keyword analysis result
 */
function analyzeUrlKeywords(url) {
  const result = {
    matchedCategories: [],
    matches: [],
    score: 0
  };

  if (!adultKeywords || !url || !contentFilterSettings) {
    return result;
  }

  const urlLower = url.toLowerCase();
  const urlParts = urlLower.split(/[\/\.\-\_\?\&\=]/);

  // Check adult content
  if (contentFilterSettings.adult?.enabled) {
    const strictness = contentFilterSettings.adult.strictness;
    const keywordsToCheck = strictness === 'high'
      ? [...adultKeywords.categories.adult.explicit, ...adultKeywords.categories.adult.moderate]
      : adultKeywords.categories.adult.explicit;

    for (const keyword of keywordsToCheck) {
      if (urlParts.includes(keyword) || urlLower.includes(keyword)) {
        result.matchedCategories.push('adult');
        result.matches.push({ category: 'adult', keyword });
        result.score += strictness === 'high' ? 80 : 60;
      }
    }
  }

  // Check gambling content
  if (contentFilterSettings.gambling?.enabled) {
    for (const keyword of adultKeywords.categories.gambling.keywords || []) {
      if (urlParts.includes(keyword) || urlLower.includes(keyword)) {
        result.matchedCategories.push('gambling');
        result.matches.push({ category: 'gambling', keyword });
        result.score += 50;
      }
    }
  }

  // Check violence content
  if (contentFilterSettings.violence?.enabled) {
    for (const keyword of adultKeywords.categories.violence.keywords || []) {
      if (urlParts.includes(keyword) || urlLower.includes(keyword)) {
        result.matchedCategories.push('violence');
        result.matches.push({ category: 'violence', keyword });
        result.score += 50;
      }
    }
  }

  // Check drugs content
  if (contentFilterSettings.drugs?.enabled) {
    for (const keyword of adultKeywords.categories.drugs.keywords || []) {
      if (urlParts.includes(keyword) || urlLower.includes(keyword)) {
        result.matchedCategories.push('drugs');
        result.matches.push({ category: 'drugs', keyword });
        result.score += 40;
      }
    }
  }

  // Check piracy content
  if (contentFilterSettings.piracy?.enabled) {
    for (const keyword of adultKeywords.categories.piracy.keywords || []) {
      if (urlParts.includes(keyword) || urlLower.includes(keyword)) {
        result.matchedCategories.push('piracy');
        result.matches.push({ category: 'piracy', keyword });
        result.score += 40;
      }
    }
  }

  // Remove duplicates
  result.matchedCategories = [...new Set(result.matchedCategories)];
  result.score = Math.min(result.score, 100);

  return result;
}

/**
 * Determine content category for a URL
 * @param {string} url - URL to categorize
 * @returns {Object} Category determination result
 */
function getCategoryForUrl(url) {
  const result = {
    categories: [],
    primaryCategory: null,
    shouldBlock: false,
    score: 0,
    reason: null
  };

  // Check cache
  const cached = contentFilterCache.get(url);
  if (cached && Date.now() - cached.timestamp < 60000) { // 1 minute cache
    return cached.result;
  }

  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;

    // Check domain blocklist first
    const blocklistCheck = checkDomainBlocklist(domain);
    if (blocklistCheck.isBlocked) {
      result.categories = blocklistCheck.categories;
      result.primaryCategory = blocklistCheck.categories[0];
      result.shouldBlock = true;
      result.score = blocklistCheck.score;
      result.reason = `Domain blocked for ${blocklistCheck.categories.join(', ')} content`;

      contentFilterCache.set(url, { result, timestamp: Date.now() });
      return result;
    }

    // Analyze URL keywords
    const keywordAnalysis = analyzeUrlKeywords(url);
    if (keywordAnalysis.matchedCategories.length > 0) {
      result.categories = keywordAnalysis.matchedCategories;
      result.primaryCategory = keywordAnalysis.matchedCategories[0];
      result.score = keywordAnalysis.score;
      result.reason = `URL contains ${keywordAnalysis.matches.map(m => m.keyword).join(', ')}`;

      // Determine if should block based on score
      if (result.score >= 50) {
        result.shouldBlock = true;
      }
    }

  } catch (error) {
    console.warn('[Security] Content categorization error:', error);
  }

  contentFilterCache.set(url, { result, timestamp: Date.now() });
  return result;
}

/**
 * Detect if URL is a search engine
 * @param {string} url - URL to check
 * @returns {Object} Search engine detection result
 */
function isSearchEngine(url) {
  const result = {
    isSearchEngine: false,
    engine: null,
    hasQuery: false
  };

  if (!adultKeywords) return result;

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();

    const searchEngines = {
      google: ['google.com', 'google.co.', 'www.google.'],
      bing: ['bing.com', 'www.bing.com'],
      duckduckgo: ['duckduckgo.com', 'www.duckduckgo.com'],
      yahoo: ['search.yahoo.com', 'yahoo.com'],
      yandex: ['yandex.com', 'yandex.ru']
    };

    for (const [engine, domains] of Object.entries(searchEngines)) {
      for (const domain of domains) {
        if (hostname.includes(domain)) {
          result.isSearchEngine = true;
          result.engine = engine;
          result.hasQuery = urlObj.searchParams.has('q') ||
                           urlObj.searchParams.has('query') ||
                           urlObj.searchParams.has('search');
          return result;
        }
      }
    }

  } catch (error) {
    // Invalid URL
  }

  return result;
}

/**
 * Enforce safe search on search engine URLs
 * @param {string} url - URL to modify
 * @returns {Object} Safe search enforcement result
 */
function enforceSafeSearch(url) {
  const result = {
    modified: false,
    originalUrl: url,
    safeUrl: url
  };

  if (!adultKeywords?.safeModeParams) return result;

  const searchCheck = isSearchEngine(url);
  if (!searchCheck.isSearchEngine || !searchCheck.hasQuery) {
    return result;
  }

  try {
    const urlObj = new URL(url);
    const safeParams = adultKeywords.safeModeParams[searchCheck.engine];

    if (safeParams) {
      const currentValue = urlObj.searchParams.get(safeParams.param);

      if (currentValue !== safeParams.value) {
        urlObj.searchParams.set(safeParams.param, safeParams.value);
        result.modified = true;
        result.safeUrl = urlObj.toString();
      }
    }

  } catch (error) {
    console.warn('[Security] Safe search enforcement error:', error);
  }

  return result;
}

/**
 * Analyze page content for blocked categories
 * @param {Object} pageData - Page data from content script
 * @returns {Object} Content analysis result
 */
function analyzePageContent(pageData) {
  const result = {
    matchedCategories: [],
    matches: [],
    score: 0,
    shouldBlock: false
  };

  if (!adultKeywords || !pageData || !contentFilterSettings) {
    return result;
  }

  const textContent = (pageData.textContent || '').toLowerCase();
  const title = (pageData.title || '').toLowerCase();
  const combinedText = `${title} ${textContent}`;

  // Count keyword matches per category
  const categoryMatches = {};

  for (const [category, config] of Object.entries(contentFilterSettings)) {
    if (!config.enabled) continue;

    const categoryData = adultKeywords.categories[category];
    if (!categoryData) continue;

    categoryMatches[category] = 0;

    const keywords = category === 'adult'
      ? (config.strictness === 'high'
          ? [...categoryData.explicit, ...categoryData.moderate]
          : categoryData.explicit)
      : categoryData.keywords;

    for (const keyword of keywords || []) {
      // Count occurrences
      const regex = new RegExp(`\\b${keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi');
      const matches = combinedText.match(regex);

      if (matches) {
        categoryMatches[category] += matches.length;
        result.matches.push({ category, keyword, count: matches.length });
      }
    }

    // Threshold for blocking based on keyword density
    if (categoryMatches[category] >= 3) {
      result.matchedCategories.push(category);
      result.score += Math.min(categoryMatches[category] * 10, 50);
    }
  }

  result.score = Math.min(result.score, 100);
  result.shouldBlock = result.score >= 50;

  return result;
}

/**
 * Main content check function
 * @param {string} url - URL to check
 * @returns {Object} Complete content filter result
 */
function checkUrl(url) {
  const result = {
    url: url,
    isBlocked: false,
    categories: [],
    reason: null,
    score: 0,
    safeSearchApplied: false,
    modifiedUrl: null
  };

  try {
    // Get category for URL
    const categoryResult = getCategoryForUrl(url);

    if (categoryResult.shouldBlock) {
      result.isBlocked = true;
      result.categories = categoryResult.categories;
      result.reason = categoryResult.reason;
      result.score = categoryResult.score;
    }

    // Check and enforce safe search
    if (contentFilterSettings?.adult?.enabled) {
      const safeSearchResult = enforceSafeSearch(url);
      if (safeSearchResult.modified) {
        result.safeSearchApplied = true;
        result.modifiedUrl = safeSearchResult.safeUrl;
      }
    }

  } catch (error) {
    console.error('[Security] Content check error:', error);
  }

  return result;
}

/**
 * Clear content filter cache
 */
function clearContentFilterCache() {
  contentFilterCache.clear();
}

/**
 * Get current content filter settings
 * @returns {Object} Current settings
 */
function getContentFilterSettings() {
  return { ...contentFilterSettings };
}

// Export for use in other modules
if (typeof self !== 'undefined') {
  self.initContentFilter = initContentFilter;
  self.checkUrl = checkUrl;
  self.checkDomainBlocklist = checkDomainBlocklist;
  self.analyzeUrlKeywords = analyzeUrlKeywords;
  self.getCategoryForUrl = getCategoryForUrl;
  self.enforceSafeSearch = enforceSafeSearch;
  self.isSearchEngine = isSearchEngine;
  self.analyzePageContent = analyzePageContent;
  self.updateContentFilterSettings = updateContentFilterSettings;
  self.getContentFilterSettings = getContentFilterSettings;
  self.clearContentFilterCache = clearContentFilterCache;
}
