// config.js - Centralized configuration for Cognitive Defense extension
// This file is shared across all extension components

/**
 * Core distracting sites list
 * Used by: background.js (Guardian tracking), manifest.json (content scripts)
 */
const DISTRACTING_SITES = [
    'facebook.com',
    'instagram.com',
    'tiktok.com',
    'youtube.com',
    'x.com',
    'twitter.com',
    'reddit.com',
    'netflix.com'
];

/**
 * Strict mode blocking list
 * These sites are blocked when strict mode is enabled
 * YouTube excluded to allow distraction-free mode
 */
const STRICT_MODE_SITES = [
    'facebook.com',
    'twitter.com',
    'x.com',
    'instagram.com',
    'tiktok.com',
    'reddit.com',
    'netflix.com'
];

/**
 * Content script configurations for distraction-free mode
 * Defines which elements to hide on each platform
 */
const SITE_CONFIGS = {
    'youtube.com': {
        selectors: [
            '#contents.ytd-rich-grid-renderer', // Main feed
            '#secondary-inner', // Watch page sidebar recommendations
            '#related', // Related videos
            'ytd-watch-next-secondary-results-renderer', // Sidebar alternative
            'ytd-reel-shelf-renderer', // Shorts in feed
            'ytd-rich-section-renderer', // Shorts shelf (modern)
            '#shorts-container', // Shorts section
            '#comments', // Comments section
            'ytd-comments', // Comments component
            '[page-subtype="home"] #contents' // General home feed backup
        ],
        actions: ['hide']
    },
    'tiktok.com': {
        selectors: [
            '[data-e2e="recommend-list-item-container"]', // Video containers
            '[data-e2e="nav-explore"]', // Explore tab
            '[data-e2e="feed-video"]', // Main feed video
            '.DivItemContainer', // Item containers
            '[data-e2e="comment-list"]', // Comments
            '#main-content-homepage_hot', // Hot feed
        ],
        actions: ['hide', 'disableInfiniteScroll']
    },
    'instagram.com': {
        selectors: [
            '[data-testid="explore-all-unit"]', // Explore section
            'article[role="presentation"]', // Post containers
            'article', // Generic posts
            '[data-testid="reels-tray-container"]', // Reels tray
            'div[role="tablist"] a[href*="/reels/"]', // Reels tab
            'a[href*="/explore/"]', // Explore links
            'main[role="main"] > div > div > div' // Feed container generic
        ],
        actions: ['hide']
    }
};

/**
 * Default Time Guardian limits
 */
const DEFAULT_GLOBAL_LIMIT = 600; // 10 minutes in seconds

/**
 * Time-based schedule presets for Guardian limits
 * Format: { startHour, endHour, limitMultiplier }
 */
const DEFAULT_TIME_SCHEDULES = {
    workHours: {
        name: 'Work Hours (9 AM - 5 PM)',
        startHour: 9,
        endHour: 17,
        limitMultiplier: 0.5 // 50% of normal limit during work hours
    },
    evening: {
        name: 'Evening (5 PM - 10 PM)',
        startHour: 17,
        endHour: 22,
        limitMultiplier: 1.0 // Normal limit
    },
    lateNight: {
        name: 'Late Night (10 PM - 9 AM)',
        startHour: 22,
        endHour: 9,
        limitMultiplier: 0.3 // Very strict late at night
    }
};

/**
 * Storage keys constants
 */
const STORAGE_KEYS = {
    // Session keys
    SESSION_END_TIME: 'sessionEndTime',
    PASSWORD_HASH: 'passwordHash',
    PASSWORD_SALT: 'passwordSalt',
    BLOCKED_SITES: 'blockedSites',
    STRICT_MODE: 'strictMode',
    SECURITY_LOGS: 'securityLogs',
    FAILED_UNLOCK_ATTEMPTS: 'failedUnlockAttempts',
    MAX_ATTEMPTS: 'maxAttempts',

    // Time Guardian keys
    TIME_GUARDIAN_ENABLED: 'timeGuardianEnabled',
    DAILY_USAGE: 'dailyUsage',
    GUARDIAN_LIMITS: 'timeGuardianLimits',
    LAST_RESET_DATE: 'lastResetDate',
    GUARDIAN_PASSWORD_HASH: 'guardianPasswordHash',
    GUARDIAN_PASSWORD_SALT: 'guardianPasswordSalt',
    TIME_SCHEDULES: 'timeSchedules',
    TIME_SCHEDULES_ENABLED: 'timeSchedulesEnabled',

    // Options keys
    OPTIONS_BLOCKED_SITES: 'optionsBlockedSites',
    OPTIONS_FOCUS_DURATION: 'optionsFocusDuration',
    OPTIONS_STRICT_MODE: 'optionsStrictMode',
    OPTIONS_EMERGENCY_CODE: 'optionsEmergencyCode',
    OPTIONS_MAX_ATTEMPTS: 'optionsMaxAttempts'
};

/**
 * Helper: Find matching domain from DISTRACTING_SITES
 */
function findMatchingDomain(hostname) {
    return DISTRACTING_SITES.find(site => hostname.endsWith(site)) || hostname;
}

/**
 * Helper: Check if site is in distracting sites list
 */
function isDistractingSite(hostname) {
    return DISTRACTING_SITES.some(site => hostname.endsWith(site));
}

/**
 * Helper: Get current time schedule multiplier
 * Returns the limit multiplier based on current time
 */
function getCurrentScheduleMultiplier(schedules = null) {
    if (!schedules || schedules.length === 0) {
        return 1.0; // No schedule, use default multiplier
    }

    const currentHour = new Date().getHours();

    // Find matching schedule
    for (const schedule of schedules) {
        if (schedule.enabled) {
            // Handle schedules that span midnight
            if (schedule.startHour <= schedule.endHour) {
                // Normal schedule (e.g., 9-17)
                if (currentHour >= schedule.startHour && currentHour < schedule.endHour) {
                    return schedule.limitMultiplier;
                }
            } else {
                // Spans midnight (e.g., 22-9)
                if (currentHour >= schedule.startHour || currentHour < schedule.endHour) {
                    return schedule.limitMultiplier;
                }
            }
        }
    }

    return 1.0; // No matching schedule, use default
}

// ==========================================
// Security Configuration
// ==========================================

/**
 * Security feature configuration
 */
const SECURITY_CONFIG = {
    features: {
        urlAnalysis: true,
        phishingDetection: true,
        contentFiltering: true,
        privacyProtection: true,
        safeSearchEnforcement: true
    },
    thresholds: {
        critical: 90,
        high: 70,
        medium: 40,
        low: 1
    },
    contentCategories: {
        adult: { enabled: true, strictness: 'high' },
        gambling: { enabled: false, strictness: 'medium' },
        violence: { enabled: false, strictness: 'medium' },
        drugs: { enabled: false, strictness: 'low' },
        piracy: { enabled: false, strictness: 'low' }
    },
    privacy: {
        blockTrackers: true,
        cleanUrls: true,
        trackerCategories: {
            analytics: true,
            advertising: true,
            social: false,
            fingerprinting: true
        }
    },
    alerts: {
        showNotifications: true,
        showOverlays: true,
        logAlerts: true
    }
};

/**
 * Security storage keys
 */
const SECURITY_STORAGE_KEYS = {
    SETTINGS: 'securitySettings',
    STATS: 'securityStats',
    ALERTS: 'securityAlerts',
    WHITELIST: 'securityWhitelist',
    TRACKER_STATS: 'trackerStats',
    THREATS_BLOCKED: 'threatsBlocked',
    URLS_CLEANED: 'urlsCleaned',
    PHISHING_BLOCKED: 'phishingBlocked',
    CONTENT_BLOCKED: 'contentBlocked'
};

// Export for use in different contexts
if (typeof module !== 'undefined' && module.exports) {
    // Node.js/CommonJS
    module.exports = {
        DISTRACTING_SITES,
        STRICT_MODE_SITES,
        SITE_CONFIGS,
        DEFAULT_GLOBAL_LIMIT,
        DEFAULT_TIME_SCHEDULES,
        STORAGE_KEYS,
        SECURITY_CONFIG,
        SECURITY_STORAGE_KEYS,
        findMatchingDomain,
        isDistractingSite,
        getCurrentScheduleMultiplier
    };
}
