// content.js - Content script for Cognitive Defense extension

// Configuration for different sites
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

// Global state
let isFocusModeActive = false;
let observer = null;
let currentConfig = null;
let focusIndicator = null;

// Initialize on page load
async function init() {
    const hostname = window.location.hostname.replace('www.', '');

    // Check if site is supported
    if (!SITE_CONFIGS[hostname]) {
        return; // Exit if not a supported site
    }

    currentConfig = SITE_CONFIGS[hostname];

    // Create indicator element
    createFocusIndicator();

    // Check focus mode status
    await checkFocusModeStatus();

    if (isFocusModeActive) {
        showIndicator();
        applyRestrictions();
        setupObserver();
    }
}

// Create the focus mode indicator element
function createFocusIndicator() {
    focusIndicator = document.createElement('div');
    focusIndicator.className = 'cd-focus-indicator';
    focusIndicator.textContent = 'Cognitive Defense: Focus Mode Active';
    document.body.appendChild(focusIndicator);
}

// Show/Hide indicator
function showIndicator() {
    if (focusIndicator) focusIndicator.classList.add('show');
}

function hideIndicator() {
    if (focusIndicator) focusIndicator.classList.remove('show');
}

// Check if focus mode is active by querying storage
async function checkFocusModeStatus() {
    try {
        const result = await chrome.storage.local.get(['sessionEndTime']);
        const sessionEndTime = result.sessionEndTime;

        if (sessionEndTime && Date.now() < sessionEndTime) {
            isFocusModeActive = true;
        } else {
            isFocusModeActive = false;
        }
    } catch (error) {
        console.warn('Cognitive Defense: Failed to check focus mode status', error);
        isFocusModeActive = false;
    }
}

// Apply restrictions based on site config
function applyRestrictions() {
    if (!currentConfig) return;

    currentConfig.actions.forEach(action => {
        switch (action) {
            case 'hide':
                hideElements(currentConfig.selectors);
                break;
            case 'disableInfiniteScroll':
                disableInfiniteScroll();
                break;
        }
    });
}

// Hide elements matching selectors
function hideElements(selectors) {
    selectors.forEach(selector => {
        const elements = document.querySelectorAll(selector);
        elements.forEach(element => {
            if (!element.hasAttribute('data-cd-hidden')) {
                element.style.display = 'none';
                element.setAttribute('data-cd-hidden', 'true');
            }
        });
    });
}

// Disable infinite scroll on TikTok
function disableInfiniteScroll() {
    // Hide/override load-more buttons instead
    const loadMoreSelectors = ['[data-e2e="load-more"]', '.load-more', '[data-testid="load-more"]', 'button[aria-label*="load more"]'];
    loadMoreSelectors.forEach(selector => {
        document.querySelectorAll(selector).forEach(btn => {
            btn.style.display = 'none';
            btn.disabled = true;
        });
    });
    // Re-apply via observer if needed
}

// Set up MutationObserver to handle dynamic content
function setupObserver() {
    let timeout = null;
    observer = new MutationObserver((mutations) => {
        // Debounce/Throttle
        if (timeout) return;

        timeout = setTimeout(() => {
            timeout = null;
            let shouldUpdate = false;
            // Check if relevant changes occurred
            for (const mutation of mutations) {
                if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                    shouldUpdate = true;
                    break;
                }
            }
            if (shouldUpdate) {
                applyRestrictions();
            }
        }, 500); // 500ms throttle
    });

    // Observe changes to the entire document body
    // Consider observing a more specific container if possible, but body is safest for generic support
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
}

// Listen for storage changes to update focus mode status
chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'local' && changes.sessionEndTime) {
        checkFocusModeStatus().then(() => {
            if (isFocusModeActive) {
                showIndicator();
                applyRestrictions();
                if (!observer) setupObserver();
            } else {
                // Focus mode ended, restore elements
                hideIndicator();
                restoreElements();
                if (observer) {
                    observer.disconnect();
                    observer = null;
                }
            }
        });
    }
});

// Restore hidden elements when focus mode ends
function restoreElements() {
    const hiddenElements = document.querySelectorAll('[data-cd-hidden]');
    hiddenElements.forEach(element => {
        element.style.display = '';
        element.removeAttribute('data-cd-hidden');
    });

    // Restore disabled elements
    const disabledElements = document.querySelectorAll('[data-cd-disabled]');
    disabledElements.forEach(element => {
        element.style.display = '';
        element.removeAttribute('data-cd-disabled');
    });
}

// Handle page unload/reload to prevent bypass
window.addEventListener('beforeunload', () => {
    // Ensure restrictions are maintained across reloads
    if (isFocusModeActive) {
        // This will be re-applied on load, but we can add a brief overlay if needed
        // For now, rely on storage check on init
    }
});

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}