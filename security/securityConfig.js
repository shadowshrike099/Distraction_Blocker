/**
 * @fileoverview Security Configuration Constants
 * @description Contains all security-related configuration constants and default settings
 * @version 1.0.0
 */

/**
 * Security feature flags and thresholds
 * @constant {Object}
 */
const SECURITY_FEATURES = {
  urlAnalysis: true,
  phishingDetection: true,
  contentFiltering: true,
  privacyProtection: true,
  safeSearchEnforcement: true,
  homographDetection: true,
  typosquattingDetection: true,
  trackerBlocking: true
};

/**
 * Threat level thresholds for classification
 * @constant {Object}
 */
const THREAT_THRESHOLDS = {
  CRITICAL: 90,
  HIGH: 70,
  MEDIUM: 40,
  LOW: 1
};

/**
 * Threat level constants
 * @constant {Object}
 */
const THREAT_LEVELS = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  NONE: 'NONE'
};

/**
 * Recommendation actions
 * @constant {Object}
 */
const RECOMMENDATIONS = {
  BLOCK: 'BLOCK',
  WARN: 'WARN',
  ALLOW: 'ALLOW'
};

/**
 * URL Shortener domains
 * @constant {Array<string>}
 */
const URL_SHORTENERS = [
  'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl',
  'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc',
  'lnkd.in', 'db.tt', 'qr.ae', 'cur.lv', 'ity.im',
  'q.gs', 'po.st', 'bc.vc', 'u.to', 'j.mp',
  'v.gd', 'x.co', 'shorte.st', 'tr.im', 'link.zip.net',
  'cutt.ly', 'rb.gy', 'shorturl.at', 'trib.al', 'clicky.me',
  'bl.ink', 's.id', 't.ly', 'rebrand.ly', 'short.io'
];

/**
 * Suspicious URL patterns
 * @constant {Array<Object>}
 */
const SUSPICIOUS_PATTERNS = [
  { pattern: /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, score: 25, type: 'ip_address', detail: 'Direct IP address access' },
  { pattern: /-{2,}/, score: 10, type: 'multiple_hyphens', detail: 'Multiple consecutive hyphens' },
  { pattern: /\.(exe|msi|bat|cmd|ps1|vbs|js|jar|scr|pif)$/i, score: 35, type: 'executable', detail: 'Executable file extension' },
  { pattern: /(login|signin|account|secure|verify|update|confirm)/i, score: 10, type: 'sensitive_keywords', detail: 'Contains sensitive keywords' },
  { pattern: /\..*\./g, score: 5, type: 'subdomain_depth', detail: 'Deep subdomain structure' },
  { pattern: /@/, score: 20, type: 'at_symbol', detail: 'Contains @ symbol in URL' },
  { pattern: /\.(tk|ml|ga|cf|gq)$/i, score: 25, type: 'free_tld', detail: 'Free TLD often used for phishing' },
  { pattern: /%[0-9a-f]{2}/i, score: 5, type: 'encoded_chars', detail: 'URL-encoded characters' },
  { pattern: /data:/i, score: 40, type: 'data_uri', detail: 'Data URI scheme' },
  { pattern: /javascript:/i, score: 45, type: 'javascript_uri', detail: 'JavaScript URI scheme' }
];

/**
 * Default content filtering settings
 * @constant {Object}
 */
const DEFAULT_CONTENT_SETTINGS = {
  adult: { enabled: true, strictness: 'high' },
  gambling: { enabled: false, strictness: 'medium' },
  violence: { enabled: false, strictness: 'medium' },
  drugs: { enabled: false, strictness: 'low' },
  piracy: { enabled: false, strictness: 'low' }
};

/**
 * Default privacy settings
 * @constant {Object}
 */
const DEFAULT_PRIVACY_SETTINGS = {
  blockTrackers: true,
  cleanUrls: true,
  trackerCategories: {
    analytics: true,
    advertising: true,
    social: false,
    fingerprinting: true
  }
};

/**
 * Default alert settings
 * @constant {Object}
 */
const DEFAULT_ALERT_SETTINGS = {
  showNotifications: true,
  showOverlays: true,
  logAlerts: true,
  maxAlertHistory: 100
};

// Note: SECURITY_STORAGE_KEYS is defined in config.js to avoid duplication

/**
 * Cache expiration times (in milliseconds)
 * @constant {Object}
 */
const CACHE_EXPIRY = {
  URL_ANALYSIS: 5 * 60 * 1000,  // 5 minutes
  PAGE_ANALYSIS: 10 * 60 * 1000, // 10 minutes
  DATA_FILES: 60 * 60 * 1000     // 1 hour
};

/**
 * Levenshtein distance threshold for typosquatting detection
 * @constant {number}
 */
const TYPOSQUATTING_THRESHOLD = 3;

/**
 * Entropy threshold for suspicious domain detection
 * @constant {number}
 */
const ENTROPY_THRESHOLD = 4.0;

/**
 * Maximum domain length before flagging
 * @constant {number}
 */
const MAX_DOMAIN_LENGTH = 50;

// Export for use in other modules
// Note: SECURITY_STORAGE_KEYS is exported from config.js
if (typeof self !== 'undefined') {
  self.SECURITY_FEATURES = SECURITY_FEATURES;
  self.THREAT_THRESHOLDS = THREAT_THRESHOLDS;
  self.THREAT_LEVELS = THREAT_LEVELS;
  self.RECOMMENDATIONS = RECOMMENDATIONS;
  self.URL_SHORTENERS = URL_SHORTENERS;
  self.SUSPICIOUS_PATTERNS = SUSPICIOUS_PATTERNS;
  self.DEFAULT_CONTENT_SETTINGS = DEFAULT_CONTENT_SETTINGS;
  self.DEFAULT_PRIVACY_SETTINGS = DEFAULT_PRIVACY_SETTINGS;
  self.DEFAULT_ALERT_SETTINGS = DEFAULT_ALERT_SETTINGS;
  self.CACHE_EXPIRY = CACHE_EXPIRY;
  self.TYPOSQUATTING_THRESHOLD = TYPOSQUATTING_THRESHOLD;
  self.ENTROPY_THRESHOLD = ENTROPY_THRESHOLD;
  self.MAX_DOMAIN_LENGTH = MAX_DOMAIN_LENGTH;
}
