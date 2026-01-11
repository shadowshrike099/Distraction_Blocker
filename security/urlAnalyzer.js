/**
 * @fileoverview URL Security Analyzer
 * @description Comprehensive URL analysis including homograph detection, typosquatting, and pattern analysis
 * @version 1.0.0
 */

// Module state
let homoglyphMap = null;
let brandDatabase = null;
let tldRiskScores = null;
let maliciousDomains = null;
let urlAnalysisCache = new Map();

/**
 * Initialize the URL analyzer with required data
 * @async
 * @returns {Promise<boolean>} Success status
 */
async function initUrlAnalyzer() {
  try {
    const [homoglyphData, brandData, tldData, maliciousData] = await Promise.all([
      fetch(chrome.runtime.getURL('data/homoglyphMap.json')).then(r => r.json()),
      fetch(chrome.runtime.getURL('data/brandDatabase.json')).then(r => r.json()),
      fetch(chrome.runtime.getURL('data/tldRiskScores.json')).then(r => r.json()),
      fetch(chrome.runtime.getURL('data/maliciousDomains.json')).then(r => r.json())
    ]);

    homoglyphMap = homoglyphData;
    brandDatabase = brandData;
    tldRiskScores = tldData;
    maliciousDomains = maliciousData;

    console.log('[Security] URL Analyzer initialized successfully');
    return true;
  } catch (error) {
    console.error('[Security] Failed to initialize URL Analyzer:', error);
    return false;
  }
}

/**
 * Calculate Levenshtein distance between two strings
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {number} Edit distance between strings
 */
function levenshteinDistance(a, b) {
  if (!a || !b) return Math.max(a?.length || 0, b?.length || 0);

  const matrix = [];

  // Initialize matrix
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  // Fill matrix
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

/**
 * Calculate Shannon entropy of a string
 * @param {string} str - Input string
 * @returns {number} Entropy value
 */
function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;

  const frequencies = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;

  for (const char in frequencies) {
    const probability = frequencies[char] / len;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

/**
 * Detect homograph attacks using Unicode lookalike characters
 * @param {string} domain - Domain to analyze
 * @returns {Object} Homograph detection result
 */
function detectHomograph(domain) {
  const result = {
    hasHomograph: false,
    homoglyphs: [],
    normalizedDomain: domain,
    score: 0
  };

  if (!homoglyphMap || !domain) return result;

  let normalized = domain;
  const found = [];

  // Check Cyrillic characters
  for (const [cyrillic, info] of Object.entries(homoglyphMap.cyrillicToLatin)) {
    if (domain.includes(cyrillic)) {
      found.push({
        original: cyrillic,
        replacement: info.latin,
        type: 'cyrillic',
        unicode: info.unicode,
        name: info.name
      });
      normalized = normalized.split(cyrillic).join(info.latin);
    }
  }

  // Check Greek characters
  for (const [greek, info] of Object.entries(homoglyphMap.greekToLatin)) {
    if (domain.includes(greek)) {
      found.push({
        original: greek,
        replacement: info.latin,
        type: 'greek',
        unicode: info.unicode,
        name: info.name
      });
      normalized = normalized.split(greek).join(info.latin);
    }
  }

  // Check special characters
  for (const [special, info] of Object.entries(homoglyphMap.specialCharacters)) {
    if (domain.includes(special)) {
      found.push({
        original: special,
        replacement: info.lookalike,
        type: 'special',
        unicode: info.unicode,
        name: info.name || 'Special character'
      });
      normalized = normalized.split(special).join(info.lookalike);
    }
  }

  // Check number substitutions (both directions)
  for (const [num, info] of Object.entries(homoglyphMap.numberLetterSubstitutions)) {
    if (domain.includes(num)) {
      // Only flag if it looks like intentional substitution
      const letterVariant = domain.replace(num, info.lookalike.toLowerCase());
      if (brandDatabase?.brands.some(b =>
        b.legitimateDomains.some(d => d.includes(letterVariant))
      )) {
        found.push({
          original: num,
          replacement: info.lookalike,
          type: 'number_substitution'
        });
      }
    }
  }

  if (found.length > 0) {
    result.hasHomograph = true;
    result.homoglyphs = found;
    result.normalizedDomain = normalized;
    // Score based on number of homoglyphs found
    result.score = Math.min(found.length * 15, 45);
  }

  return result;
}

/**
 * Detect typosquatting attempts against known brands
 * @param {string} domain - Domain to check
 * @returns {Object} Typosquatting detection result
 */
function detectTyposquatting(domain) {
  const result = {
    isTyposquatting: false,
    targetBrand: null,
    distance: Infinity,
    matchedDomain: null,
    score: 0
  };

  if (!brandDatabase || !domain) return result;

  // Remove TLD for comparison
  const domainParts = domain.split('.');
  const domainWithoutTld = domainParts.slice(0, -1).join('.');

  for (const brand of brandDatabase.brands) {
    // Check against brand keywords
    for (const keyword of brand.keywords) {
      // Check if domain contains a misspelling of the keyword
      if (domainWithoutTld.includes(keyword)) {
        continue; // Exact match, not typosquatting
      }

      const distance = levenshteinDistance(domainWithoutTld, keyword);

      if (distance <= TYPOSQUATTING_THRESHOLD && distance < result.distance) {
        // Check if this is a legitimate domain
        const isLegitimate = brand.legitimateDomains.some(legit => {
          if (legit.includes('*')) {
            const pattern = legit.replace(/\*/g, '.*');
            return new RegExp(pattern).test(domain);
          }
          return domain === legit || domain.endsWith('.' + legit);
        });

        if (!isLegitimate) {
          result.isTyposquatting = true;
          result.targetBrand = brand.name;
          result.distance = distance;
          result.matchedDomain = keyword;
          result.priority = brand.priority;
          result.score = (TYPOSQUATTING_THRESHOLD - distance + 1) * 20;
        }
      }
    }
  }

  return result;
}

/**
 * Analyze URL for suspicious patterns
 * @param {string} url - URL to analyze
 * @returns {Object} Pattern analysis result
 */
function analyzeSuspiciousPatterns(url) {
  const result = {
    suspiciousPatterns: [],
    totalScore: 0
  };

  if (!url) return result;

  try {
    const urlObj = new URL(url);
    const fullUrl = url.toLowerCase();
    const hostname = urlObj.hostname.toLowerCase();

    // Check configured suspicious patterns
    for (const patternConfig of SUSPICIOUS_PATTERNS) {
      const regex = patternConfig.pattern instanceof RegExp
        ? patternConfig.pattern
        : new RegExp(patternConfig.pattern, 'i');

      if (regex.test(fullUrl)) {
        result.suspiciousPatterns.push({
          type: patternConfig.type,
          detail: patternConfig.detail,
          score: patternConfig.score
        });
        result.totalScore += patternConfig.score;
      }
    }

    // Check domain length
    if (hostname.length > MAX_DOMAIN_LENGTH) {
      result.suspiciousPatterns.push({
        type: 'long_domain',
        detail: `Domain exceeds ${MAX_DOMAIN_LENGTH} characters`,
        score: 15
      });
      result.totalScore += 15;
    }

    // Check for excessive subdomains
    const subdomainCount = hostname.split('.').length - 2;
    if (subdomainCount > 3) {
      result.suspiciousPatterns.push({
        type: 'excessive_subdomains',
        detail: `${subdomainCount} subdomains detected`,
        score: subdomainCount * 5
      });
      result.totalScore += subdomainCount * 5;
    }

    // Check entropy of domain name
    const entropy = calculateEntropy(hostname.replace(/\./g, ''));
    if (entropy > ENTROPY_THRESHOLD) {
      result.suspiciousPatterns.push({
        type: 'high_entropy',
        detail: `High randomness in domain (entropy: ${entropy.toFixed(2)})`,
        score: 10
      });
      result.totalScore += 10;
    }

    // Check for brand keywords in non-brand domains
    if (brandDatabase) {
      for (const brand of brandDatabase.brands) {
        for (const keyword of brand.keywords) {
          if (hostname.includes(keyword)) {
            const isLegitimate = brand.legitimateDomains.some(legit => {
              if (legit.includes('*')) {
                const pattern = legit.replace(/\*/g, '.*');
                return new RegExp(pattern).test(hostname);
              }
              return hostname === legit || hostname.endsWith('.' + legit);
            });

            if (!isLegitimate) {
              result.suspiciousPatterns.push({
                type: 'brand_keyword_misuse',
                detail: `Contains "${keyword}" but is not a legitimate ${brand.name} domain`,
                score: brand.priority === 'critical' ? 30 : 20
              });
              result.totalScore += brand.priority === 'critical' ? 30 : 20;
            }
          }
        }
      }
    }

  } catch (error) {
    console.warn('[Security] Pattern analysis error:', error);
  }

  return result;
}

/**
 * Assess risk based on TLD
 * @param {string} tld - Top-level domain (with dot)
 * @returns {Object} TLD risk assessment
 */
function assessTldRisk(tld) {
  const result = {
    tld: tld,
    riskLevel: 'low',
    score: 0,
    reason: 'Standard TLD'
  };

  if (!tldRiskScores || !tld) return result;

  const tldLower = tld.toLowerCase();

  // Check high risk TLDs
  if (tldRiskScores.highRisk.tlds.includes(tldLower)) {
    result.riskLevel = 'high';
    result.score = tldRiskScores.highRisk.score;
    result.reason = tldRiskScores.highRisk.reason;
    return result;
  }

  // Check medium risk TLDs
  if (tldRiskScores.mediumRisk.tlds.includes(tldLower)) {
    result.riskLevel = 'medium';
    result.score = tldRiskScores.mediumRisk.score;
    result.reason = tldRiskScores.mediumRisk.reason;
    return result;
  }

  // Check special purpose TLDs
  for (const [key, special] of Object.entries(tldRiskScores.specialPurpose)) {
    if (tldLower === special.tld) {
      result.riskLevel = 'high';
      result.score = special.score;
      result.reason = special.reason;
      return result;
    }
  }

  // Check country TLDs
  for (const [level, data] of Object.entries(tldRiskScores.countryTlds)) {
    if (data.tlds.includes(tldLower)) {
      result.riskLevel = level;
      result.score = data.score;
      result.reason = `${level.charAt(0).toUpperCase() + level.slice(1)} trust country TLD`;
      return result;
    }
  }

  // Low risk TLDs
  if (tldRiskScores.lowRisk.tlds.includes(tldLower)) {
    result.riskLevel = 'low';
    result.score = tldRiskScores.lowRisk.score;
    result.reason = tldRiskScores.lowRisk.reason;
  }

  return result;
}

/**
 * Check if URL is from a URL shortener service
 * @param {string} domain - Domain to check
 * @returns {Object} URL shortener detection result
 */
function isUrlShortener(domain) {
  const result = {
    isShortener: false,
    service: null,
    score: 0
  };

  if (!domain) return result;

  const domainLower = domain.toLowerCase();

  for (const shortener of URL_SHORTENERS) {
    if (domainLower === shortener || domainLower.endsWith('.' + shortener)) {
      result.isShortener = true;
      result.service = shortener;
      result.score = 15;
      break;
    }
  }

  return result;
}

/**
 * Check against known malicious domains database
 * @param {string} domain - Domain to check
 * @returns {Object} Malicious domain check result
 */
function checkMaliciousDomain(domain) {
  const result = {
    isMalicious: false,
    type: null,
    score: 0
  };

  if (!maliciousDomains || !domain) return result;

  const domainLower = domain.toLowerCase();

  // Check direct matches
  for (const type of ['phishing', 'malware', 'scam']) {
    if (maliciousDomains[type]?.includes(domainLower)) {
      result.isMalicious = true;
      result.type = type;
      result.score = 100; // Immediate block
      return result;
    }
  }

  // Check patterns
  for (const pattern of maliciousDomains.patterns || []) {
    try {
      const regex = new RegExp(pattern.pattern, 'i');
      if (regex.test(domainLower)) {
        result.isMalicious = true;
        result.type = pattern.type;
        result.score = pattern.score;
        return result;
      }
    } catch (e) {
      // Invalid regex, skip
    }
  }

  return result;
}

/**
 * Main URL analysis function
 * @async
 * @param {string} url - URL to analyze
 * @returns {Promise<Object>} Complete threat assessment
 */
async function analyzeUrl(url) {
  // Check cache first
  const cached = urlAnalysisCache.get(url);
  if (cached && Date.now() - cached.timestamp < CACHE_EXPIRY.URL_ANALYSIS) {
    return cached.result;
  }

  const result = {
    url: url,
    threatScore: 0,
    threatLevel: THREAT_LEVELS.NONE,
    flags: [],
    recommendation: RECOMMENDATIONS.ALLOW,
    analysis: {
      homograph: null,
      typosquatting: null,
      patterns: null,
      tld: null,
      shortener: null,
      malicious: null
    },
    timestamp: Date.now()
  };

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const tld = '.' + hostname.split('.').pop();

    // Run all analyses
    result.analysis.homograph = detectHomograph(hostname);
    result.analysis.typosquatting = detectTyposquatting(hostname);
    result.analysis.patterns = analyzeSuspiciousPatterns(url);
    result.analysis.tld = assessTldRisk(tld);
    result.analysis.shortener = isUrlShortener(hostname);
    result.analysis.malicious = checkMaliciousDomain(hostname);

    // Aggregate flags and scores
    if (result.analysis.homograph.hasHomograph) {
      result.flags.push({
        type: 'homograph',
        detail: `Lookalike characters detected: ${result.analysis.homograph.homoglyphs.map(h => h.original).join(', ')}`,
        score: result.analysis.homograph.score
      });
      result.threatScore += result.analysis.homograph.score;
    }

    if (result.analysis.typosquatting.isTyposquatting) {
      result.flags.push({
        type: 'typosquatting',
        detail: `Possible impersonation of ${result.analysis.typosquatting.targetBrand}`,
        score: result.analysis.typosquatting.score
      });
      result.threatScore += result.analysis.typosquatting.score;
    }

    if (result.analysis.patterns.suspiciousPatterns.length > 0) {
      for (const pattern of result.analysis.patterns.suspiciousPatterns) {
        result.flags.push(pattern);
      }
      result.threatScore += result.analysis.patterns.totalScore;
    }

    if (result.analysis.tld.score > 0) {
      result.flags.push({
        type: 'risky_tld',
        detail: `${result.analysis.tld.tld}: ${result.analysis.tld.reason}`,
        score: result.analysis.tld.score
      });
      result.threatScore += result.analysis.tld.score;
    }

    if (result.analysis.shortener.isShortener) {
      result.flags.push({
        type: 'url_shortener',
        detail: `URL shortener detected: ${result.analysis.shortener.service}`,
        score: result.analysis.shortener.score
      });
      result.threatScore += result.analysis.shortener.score;
    }

    if (result.analysis.malicious.isMalicious) {
      result.flags.push({
        type: 'malicious_domain',
        detail: `Known ${result.analysis.malicious.type} domain`,
        score: result.analysis.malicious.score
      });
      result.threatScore += result.analysis.malicious.score;
    }

    // Cap score at 100
    result.threatScore = Math.min(result.threatScore, 100);

    // Determine threat level
    if (result.threatScore >= THREAT_THRESHOLDS.CRITICAL) {
      result.threatLevel = THREAT_LEVELS.CRITICAL;
      result.recommendation = RECOMMENDATIONS.BLOCK;
    } else if (result.threatScore >= THREAT_THRESHOLDS.HIGH) {
      result.threatLevel = THREAT_LEVELS.HIGH;
      result.recommendation = RECOMMENDATIONS.BLOCK;
    } else if (result.threatScore >= THREAT_THRESHOLDS.MEDIUM) {
      result.threatLevel = THREAT_LEVELS.MEDIUM;
      result.recommendation = RECOMMENDATIONS.WARN;
    } else if (result.threatScore >= THREAT_THRESHOLDS.LOW) {
      result.threatLevel = THREAT_LEVELS.LOW;
      result.recommendation = RECOMMENDATIONS.ALLOW;
    }

  } catch (error) {
    console.error('[Security] URL analysis error:', error);
    result.flags.push({
      type: 'analysis_error',
      detail: 'Failed to analyze URL',
      score: 0
    });
  }

  // Cache result
  urlAnalysisCache.set(url, { result, timestamp: Date.now() });

  // Cleanup old cache entries periodically
  if (urlAnalysisCache.size > 1000) {
    const now = Date.now();
    for (const [key, value] of urlAnalysisCache) {
      if (now - value.timestamp > CACHE_EXPIRY.URL_ANALYSIS) {
        urlAnalysisCache.delete(key);
      }
    }
  }

  return result;
}

/**
 * Clear the URL analysis cache
 */
function clearUrlAnalysisCache() {
  urlAnalysisCache.clear();
}

// Export for use in other modules
if (typeof self !== 'undefined') {
  self.initUrlAnalyzer = initUrlAnalyzer;
  self.analyzeUrl = analyzeUrl;
  self.detectHomograph = detectHomograph;
  self.detectTyposquatting = detectTyposquatting;
  self.analyzeSuspiciousPatterns = analyzeSuspiciousPatterns;
  self.assessTldRisk = assessTldRisk;
  self.isUrlShortener = isUrlShortener;
  self.levenshteinDistance = levenshteinDistance;
  self.calculateEntropy = calculateEntropy;
  self.clearUrlAnalysisCache = clearUrlAnalysisCache;
}
