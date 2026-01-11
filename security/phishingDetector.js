/**
 * @fileoverview Phishing Detection Module
 * @description Analyzes page content for phishing indicators
 * @version 1.0.0
 */

// Module state
let phishingPatterns = null;
let brandDatabasePhishing = null;
let pageAnalysisCache = new Map();

/**
 * Initialize the phishing detector with required data
 * @async
 * @returns {Promise<boolean>} Success status
 */
async function initPhishingDetector() {
  try {
    const [patternsData, brandData] = await Promise.all([
      fetch(chrome.runtime.getURL('data/phishingPatterns.json')).then(r => r.json()),
      fetch(chrome.runtime.getURL('data/brandDatabase.json')).then(r => r.json())
    ]);

    phishingPatterns = patternsData;
    brandDatabasePhishing = brandData;

    console.log('[Security] Phishing Detector initialized successfully');
    return true;
  } catch (error) {
    console.error('[Security] Failed to initialize Phishing Detector:', error);
    return false;
  }
}

/**
 * Detect login forms on a page
 * @param {Object} pageData - Page data from content script
 * @returns {Object} Login form detection result
 */
function detectLoginForms(pageData) {
  const result = {
    hasLoginForm: false,
    forms: [],
    score: 0
  };

  if (!pageData.forms || pageData.forms.length === 0) {
    return result;
  }

  for (const form of pageData.forms) {
    const formAnalysis = {
      hasPasswordField: false,
      hasUsernameField: false,
      hasEmailField: false,
      action: form.action || '',
      method: form.method || 'GET',
      inputFields: form.inputs || []
    };

    // Check for password fields
    for (const input of form.inputs || []) {
      if (input.type === 'password') {
        formAnalysis.hasPasswordField = true;
      }
      if (input.type === 'email' || input.name?.toLowerCase().includes('email')) {
        formAnalysis.hasEmailField = true;
      }
      if (input.type === 'text' && (
        input.name?.toLowerCase().includes('user') ||
        input.name?.toLowerCase().includes('login') ||
        input.name?.toLowerCase().includes('name')
      )) {
        formAnalysis.hasUsernameField = true;
      }
    }

    if (formAnalysis.hasPasswordField) {
      result.hasLoginForm = true;
      result.forms.push(formAnalysis);
    }
  }

  if (result.hasLoginForm) {
    result.score = 10; // Base score for having login form
  }

  return result;
}

/**
 * Analyze form action URLs for suspicious destinations
 * @param {Array} forms - Forms from login detection
 * @param {string} currentDomain - Current page domain
 * @returns {Object} Form action analysis result
 */
function analyzeFormActions(forms, currentDomain) {
  const result = {
    suspiciousActions: [],
    score: 0
  };

  if (!forms || forms.length === 0) {
    return result;
  }

  for (const form of forms) {
    if (!form.action || form.action === '' || form.action === '#') {
      // Form submits to same page or no action
      continue;
    }

    try {
      const actionUrl = new URL(form.action, `https://${currentDomain}`);
      const actionDomain = actionUrl.hostname;

      // Check if form submits to a different domain
      if (actionDomain !== currentDomain && !actionDomain.endsWith('.' + currentDomain)) {
        result.suspiciousActions.push({
          type: 'cross_domain_submit',
          detail: `Form submits to external domain: ${actionDomain}`,
          actionUrl: form.action
        });
        result.score += 25;
      }

      // Check if form submits to IP address
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(actionDomain)) {
        result.suspiciousActions.push({
          type: 'ip_submit',
          detail: 'Form submits to IP address',
          actionUrl: form.action
        });
        result.score += 30;
      }

      // Check for HTTP on login form
      if (form.hasPasswordField && actionUrl.protocol === 'http:') {
        result.suspiciousActions.push({
          type: 'insecure_submit',
          detail: 'Password submitted over insecure HTTP',
          actionUrl: form.action
        });
        result.score += 20;
      }

      // Check for data: or javascript: protocols
      if (form.action.startsWith('data:') || form.action.startsWith('javascript:')) {
        result.suspiciousActions.push({
          type: 'suspicious_protocol',
          detail: 'Form uses suspicious protocol',
          actionUrl: form.action
        });
        result.score += 35;
      }

    } catch (error) {
      // Invalid URL in action
      result.suspiciousActions.push({
        type: 'invalid_action',
        detail: 'Form has invalid action URL',
        actionUrl: form.action
      });
      result.score += 10;
    }
  }

  return result;
}

/**
 * Detect brand impersonation based on page content and domain
 * @param {Object} pageData - Page data from content script
 * @param {string} currentDomain - Current page domain
 * @returns {Object} Brand impersonation detection result
 */
function detectBrandImpersonation(pageData, currentDomain) {
  const result = {
    isImpersonating: false,
    impersonatedBrand: null,
    indicators: [],
    score: 0
  };

  if (!brandDatabasePhishing || !pageData) {
    return result;
  }

  // Whitelist of trusted domains that should never be flagged for brand impersonation
  // These are legitimate sites that may display content about other brands
  const trustedDomains = [
    'google.com', 'google.co', 'www.google.',
    'bing.com', 'www.bing.com',
    'yahoo.com', 'search.yahoo.com',
    'duckduckgo.com', 'www.duckduckgo.com',
    'yandex.com', 'yandex.ru',
    'baidu.com', 'www.baidu.com',
    'youtube.com', 'www.youtube.com',
    'wikipedia.org', 'en.wikipedia.org',
    'reddit.com', 'www.reddit.com',
    'twitter.com', 'x.com',
    'facebook.com', 'www.facebook.com',
    'instagram.com', 'www.instagram.com',
    'linkedin.com', 'www.linkedin.com',
    'github.com', 'www.github.com',
    'stackoverflow.com', 'www.stackoverflow.com',
    'amazon.com', 'www.amazon.',
    'ebay.com', 'www.ebay.com',
    'cnn.com', 'bbc.com', 'nytimes.com',
    'medium.com', 'quora.com'
  ];

  const domainLower = currentDomain.toLowerCase();

  // Check if current domain is trusted - skip brand impersonation check
  const isTrustedDomain = trustedDomains.some(trusted =>
    domainLower === trusted ||
    domainLower.endsWith('.' + trusted) ||
    domainLower.includes(trusted)
  );

  if (isTrustedDomain) {
    return result; // Don't flag trusted domains
  }

  const pageText = (pageData.title + ' ' + pageData.textContent).toLowerCase();

  for (const brand of brandDatabasePhishing.brands) {
    // Check if page contains brand keywords
    let keywordMatches = 0;
    const foundKeywords = [];

    for (const keyword of brand.keywords) {
      if (pageText.includes(keyword.toLowerCase())) {
        keywordMatches++;
        foundKeywords.push(keyword);
      }
    }

    if (keywordMatches > 0) {
      // Check if this is a legitimate brand domain
      const isLegitimate = brand.legitimateDomains.some(legit => {
        if (legit.includes('*')) {
          const pattern = legit.replace(/\*/g, '.*');
          return new RegExp(pattern).test(domainLower);
        }
        return domainLower === legit || domainLower.endsWith('.' + legit);
      });

      if (!isLegitimate) {
        result.isImpersonating = true;
        result.impersonatedBrand = brand.name;
        result.indicators.push({
          type: 'brand_keywords',
          detail: `Page mentions ${brand.name} keywords: ${foundKeywords.join(', ')}`,
          keywords: foundKeywords
        });

        // Higher score for more keyword matches and critical brands
        const priorityMultiplier = brand.priority === 'critical' ? 2 :
                                   brand.priority === 'high' ? 1.5 : 1;
        result.score += Math.min(keywordMatches * 10 * priorityMultiplier, 40);
      }
    }

    // Check for logo references
    if (pageData.images) {
      for (const img of pageData.images) {
        const imgSrc = (img.src || '').toLowerCase();
        const imgAlt = (img.alt || '').toLowerCase();

        for (const keyword of brand.keywords) {
          if (imgSrc.includes(keyword) || imgAlt.includes(keyword)) {
            // Check if from legitimate CDN
            const isLegitimateSource = brand.legitimateDomains.some(d =>
              imgSrc.includes(d.replace('*', ''))
            );

            if (!isLegitimateSource && result.impersonatedBrand === brand.name) {
              result.indicators.push({
                type: 'brand_logo',
                detail: `Possible ${brand.name} logo from external source`
              });
              result.score += 15;
            }
          }
        }
      }
    }
  }

  return result;
}

/**
 * Detect urgency language patterns in page content
 * @param {string} textContent - Page text content
 * @returns {Object} Urgency language detection result
 */
function detectUrgencyLanguage(textContent) {
  const result = {
    hasUrgencyLanguage: false,
    matches: [],
    score: 0
  };

  if (!phishingPatterns || !textContent) {
    return result;
  }

  const textLower = textContent.toLowerCase();

  // Check urgency patterns
  for (const pattern of phishingPatterns.urgencyPatterns) {
    try {
      const regex = new RegExp(pattern.pattern, 'gi');
      const matches = textLower.match(regex);

      if (matches) {
        result.hasUrgencyLanguage = true;
        result.matches.push({
          pattern: pattern.pattern,
          category: pattern.category,
          matchCount: matches.length,
          score: pattern.score
        });
        result.score += pattern.score;
      }
    } catch (e) {
      // Invalid regex, skip
    }
  }

  // Check credential patterns
  for (const pattern of phishingPatterns.credentialPatterns) {
    try {
      const regex = new RegExp(pattern.pattern, 'gi');
      const matches = textLower.match(regex);

      if (matches) {
        result.hasUrgencyLanguage = true;
        result.matches.push({
          pattern: pattern.pattern,
          category: pattern.category,
          matchCount: matches.length,
          score: pattern.score
        });
        result.score += pattern.score;
      }
    } catch (e) {
      // Invalid regex, skip
    }
  }

  // Check reward/scam patterns
  for (const pattern of phishingPatterns.rewardPatterns) {
    try {
      const regex = new RegExp(pattern.pattern, 'gi');
      const matches = textLower.match(regex);

      if (matches) {
        result.hasUrgencyLanguage = true;
        result.matches.push({
          pattern: pattern.pattern,
          category: pattern.category,
          matchCount: matches.length,
          score: pattern.score
        });
        result.score += pattern.score;
      }
    } catch (e) {
      // Invalid regex, skip
    }
  }

  // Check impersonation patterns
  for (const pattern of phishingPatterns.impersonationPatterns) {
    try {
      const regex = new RegExp(pattern.pattern, 'gi');
      const matches = textLower.match(regex);

      if (matches) {
        result.matches.push({
          pattern: pattern.pattern,
          category: pattern.category,
          matchCount: matches.length,
          score: pattern.score
        });
        result.score += pattern.score;
      }
    } catch (e) {
      // Invalid regex, skip
    }
  }

  return result;
}

/**
 * Check for suspicious page characteristics
 * @param {Object} pageData - Page data from content script
 * @returns {Object} Page characteristics analysis
 */
function analyzePageCharacteristics(pageData) {
  const result = {
    suspiciousCharacteristics: [],
    score: 0
  };

  if (!pageData) return result;

  // Check for popup/modal login forms
  if (pageData.hasPopupLogin) {
    result.suspiciousCharacteristics.push({
      type: 'popup_login',
      detail: 'Login form in popup/modal'
    });
    result.score += 10;
  }

  // Check for disabled right-click
  if (pageData.rightClickDisabled) {
    result.suspiciousCharacteristics.push({
      type: 'right_click_disabled',
      detail: 'Right-click is disabled on page'
    });
    result.score += 15;
  }

  // Check for iframe login
  if (pageData.hasIframeLogin) {
    result.suspiciousCharacteristics.push({
      type: 'iframe_login',
      detail: 'Login form in iframe'
    });
    result.score += 20;
  }

  // Check for missing HTTPS
  if (pageData.url && pageData.url.startsWith('http://')) {
    result.suspiciousCharacteristics.push({
      type: 'no_https',
      detail: 'Page not using HTTPS'
    });
    result.score += 25;
  }

  // Check for very new domain (if available)
  if (pageData.domainAge && pageData.domainAge < 30) {
    result.suspiciousCharacteristics.push({
      type: 'new_domain',
      detail: `Domain is less than ${pageData.domainAge} days old`
    });
    result.score += 20;
  }

  // Check for hidden form fields with suspicious names
  if (pageData.hiddenFields) {
    const suspiciousNames = ['password', 'pass', 'pwd', 'creditcard', 'cc', 'ssn'];
    for (const field of pageData.hiddenFields) {
      for (const name of suspiciousNames) {
        if (field.name?.toLowerCase().includes(name)) {
          result.suspiciousCharacteristics.push({
            type: 'suspicious_hidden_field',
            detail: `Hidden field with name containing "${name}"`
          });
          result.score += 15;
          break;
        }
      }
    }
  }

  return result;
}

/**
 * Calculate overall phishing score from all indicators
 * @param {Object} indicators - All detection results
 * @returns {Object} Aggregated phishing assessment
 */
function calculatePhishingScore(indicators) {
  let totalScore = 0;
  const allFlags = [];

  // Add login form score
  if (indicators.loginForms?.hasLoginForm) {
    totalScore += indicators.loginForms.score;
    allFlags.push({
      type: 'login_form_present',
      detail: `${indicators.loginForms.forms.length} login form(s) detected`,
      score: indicators.loginForms.score
    });
  }

  // Add form action score
  if (indicators.formActions?.suspiciousActions.length > 0) {
    totalScore += indicators.formActions.score;
    for (const action of indicators.formActions.suspiciousActions) {
      allFlags.push({
        type: action.type,
        detail: action.detail,
        score: indicators.formActions.score / indicators.formActions.suspiciousActions.length
      });
    }
  }

  // Add brand impersonation score
  if (indicators.brandImpersonation?.isImpersonating) {
    totalScore += indicators.brandImpersonation.score;
    allFlags.push({
      type: 'brand_impersonation',
      detail: `Possible impersonation of ${indicators.brandImpersonation.impersonatedBrand}`,
      score: indicators.brandImpersonation.score
    });
  }

  // Add urgency language score
  if (indicators.urgencyLanguage?.hasUrgencyLanguage) {
    totalScore += indicators.urgencyLanguage.score;
    for (const match of indicators.urgencyLanguage.matches.slice(0, 5)) { // Limit to top 5
      allFlags.push({
        type: `urgency_${match.category}`,
        detail: `Detected ${match.category} pattern`,
        score: match.score
      });
    }
  }

  // Add page characteristics score
  if (indicators.pageCharacteristics?.suspiciousCharacteristics.length > 0) {
    totalScore += indicators.pageCharacteristics.score;
    for (const char of indicators.pageCharacteristics.suspiciousCharacteristics) {
      allFlags.push({
        type: char.type,
        detail: char.detail,
        score: indicators.pageCharacteristics.score / indicators.pageCharacteristics.suspiciousCharacteristics.length
      });
    }
  }

  // Cap at 100
  totalScore = Math.min(totalScore, 100);

  return {
    totalScore,
    flags: allFlags,
    threatLevel: totalScore >= THREAT_THRESHOLDS.CRITICAL ? THREAT_LEVELS.CRITICAL :
                 totalScore >= THREAT_THRESHOLDS.HIGH ? THREAT_LEVELS.HIGH :
                 totalScore >= THREAT_THRESHOLDS.MEDIUM ? THREAT_LEVELS.MEDIUM :
                 totalScore >= THREAT_THRESHOLDS.LOW ? THREAT_LEVELS.LOW :
                 THREAT_LEVELS.NONE,
    recommendation: totalScore >= THREAT_THRESHOLDS.HIGH ? RECOMMENDATIONS.BLOCK :
                    totalScore >= THREAT_THRESHOLDS.MEDIUM ? RECOMMENDATIONS.WARN :
                    RECOMMENDATIONS.ALLOW
  };
}

/**
 * Main page analysis function
 * @async
 * @param {Object} pageData - Page data from content script
 * @returns {Promise<Object>} Complete phishing assessment
 */
async function analyzePage(pageData) {
  // Create cache key
  const cacheKey = `${pageData.url}:${pageData.timestamp || Date.now()}`;

  // Check cache
  const cached = pageAnalysisCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_EXPIRY.PAGE_ANALYSIS) {
    return cached.result;
  }

  let currentDomain = '';
  try {
    currentDomain = new URL(pageData.url).hostname;
  } catch (e) {
    currentDomain = pageData.domain || '';
  }

  const indicators = {
    loginForms: detectLoginForms(pageData),
    formActions: null,
    brandImpersonation: detectBrandImpersonation(pageData, currentDomain),
    urgencyLanguage: detectUrgencyLanguage(pageData.textContent || ''),
    pageCharacteristics: analyzePageCharacteristics(pageData)
  };

  // Analyze form actions if login forms exist
  if (indicators.loginForms.hasLoginForm) {
    indicators.formActions = analyzeFormActions(indicators.loginForms.forms, currentDomain);
  }

  const assessment = calculatePhishingScore(indicators);

  const result = {
    url: pageData.url,
    domain: currentDomain,
    isPhishing: assessment.totalScore >= THREAT_THRESHOLDS.MEDIUM,
    threatScore: assessment.totalScore,
    threatLevel: assessment.threatLevel,
    recommendation: assessment.recommendation,
    flags: assessment.flags,
    indicators: indicators,
    timestamp: Date.now()
  };

  // Cache result
  pageAnalysisCache.set(cacheKey, { result, timestamp: Date.now() });

  // Cleanup old cache entries
  if (pageAnalysisCache.size > 500) {
    const now = Date.now();
    for (const [key, value] of pageAnalysisCache) {
      if (now - value.timestamp > CACHE_EXPIRY.PAGE_ANALYSIS) {
        pageAnalysisCache.delete(key);
      }
    }
  }

  return result;
}

/**
 * Clear the page analysis cache
 */
function clearPageAnalysisCache() {
  pageAnalysisCache.clear();
}

// Export for use in other modules
if (typeof self !== 'undefined') {
  self.initPhishingDetector = initPhishingDetector;
  self.analyzePage = analyzePage;
  self.detectLoginForms = detectLoginForms;
  self.analyzeFormActions = analyzeFormActions;
  self.detectBrandImpersonation = detectBrandImpersonation;
  self.detectUrgencyLanguage = detectUrgencyLanguage;
  self.calculatePhishingScore = calculatePhishingScore;
  self.clearPageAnalysisCache = clearPageAnalysisCache;
}
