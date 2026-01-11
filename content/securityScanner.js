/**
 * @fileoverview Security Scanner Content Script
 * @description Runs on all pages to detect security threats and inject warnings
 * @version 1.0.0
 */

(function() {
  'use strict';

  // Prevent multiple injections
  if (window.__cognitiveDefenseSecurityScanner) {
    return;
  }
  window.__cognitiveDefenseSecurityScanner = true;

  /**
   * Security Scanner class
   */
  class SecurityScanner {
    constructor() {
      /** @type {boolean} */
      this.initialized = false;

      /** @type {boolean} */
      this.warningDisplayed = false;

      /** @type {HTMLElement|null} */
      this.warningOverlay = null;

      /** @type {MutationObserver|null} */
      this.formObserver = null;

      this.init();
    }

    /**
     * Initialize the scanner
     */
    async init() {
      try {
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', () => this.startScanning());
        } else {
          this.startScanning();
        }

        // Listen for messages from background
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
          this.handleMessage(message, sender, sendResponse);
          return true;
        });

        this.initialized = true;
      } catch (error) {
        console.warn('[Security Scanner] Initialization error:', error);
      }
    }

    /**
     * Start scanning the page
     */
    async startScanning() {
      try {
        // Collect page data
        const pageData = this.collectPageData();

        // Send to background for analysis
        const response = await this.sendMessage('SECURITY_ANALYZE_PAGE', pageData);

        if (response && response.recommendation !== 'ALLOW') {
          // Page has security concerns
          console.log('[Security Scanner] Threat detected:', response);

          // Request warning display from background
          if (response.threatScore >= 40) {
            this.sendMessage('SECURITY_SHOW_WARNING_REQUEST', {
              url: window.location.href,
              threatData: response
            });
          }
        }

        // Set up form monitoring
        this.monitorForms();

        // Set up mutation observer for dynamic content
        this.setupMutationObserver();

      } catch (error) {
        console.warn('[Security Scanner] Scanning error:', error);
      }
    }

    /**
     * Collect page data for analysis
     * @returns {Object} Page data
     */
    collectPageData() {
      const data = {
        url: window.location.href,
        domain: window.location.hostname,
        title: document.title || '',
        timestamp: Date.now(),
        forms: [],
        textContent: '',
        images: [],
        hiddenFields: [],
        hasPopupLogin: false,
        rightClickDisabled: false,
        hasIframeLogin: false
      };

      try {
        // Get forms with password fields
        const forms = document.querySelectorAll('form');
        forms.forEach((form, index) => {
          const formData = {
            action: form.action || '',
            method: form.method || 'GET',
            inputs: []
          };

          const inputs = form.querySelectorAll('input');
          inputs.forEach(input => {
            formData.inputs.push({
              type: input.type || 'text',
              name: input.name || '',
              id: input.id || '',
              placeholder: input.placeholder || ''
            });

            // Track hidden fields
            if (input.type === 'hidden') {
              data.hiddenFields.push({
                name: input.name || '',
                id: input.id || ''
              });
            }
          });

          data.forms.push(formData);
        });

        // Check for popup/modal login forms
        const modals = document.querySelectorAll('[role="dialog"], .modal, .popup, [class*="modal"], [class*="popup"]');
        modals.forEach(modal => {
          if (modal.querySelector('input[type="password"]')) {
            data.hasPopupLogin = true;
          }
        });

        // Check for iframe login
        const iframes = document.querySelectorAll('iframe');
        iframes.forEach(iframe => {
          try {
            const iframeDoc = iframe.contentDocument || iframe.contentWindow?.document;
            if (iframeDoc && iframeDoc.querySelector('input[type="password"]')) {
              data.hasIframeLogin = true;
            }
          } catch (e) {
            // Cross-origin iframe, can't access
          }
        });

        // Get text content (limited for performance)
        const bodyText = document.body?.innerText || '';
        data.textContent = bodyText.substring(0, 10000); // Limit to 10k chars

        // Get images (limited)
        const images = document.querySelectorAll('img');
        let imgCount = 0;
        images.forEach(img => {
          if (imgCount < 20) {
            data.images.push({
              src: img.src || '',
              alt: img.alt || ''
            });
            imgCount++;
          }
        });

        // Check if right-click is disabled
        data.rightClickDisabled = this.isRightClickDisabled();

      } catch (error) {
        console.warn('[Security Scanner] Data collection error:', error);
      }

      return data;
    }

    /**
     * Check if right-click is disabled on the page
     * @returns {boolean}
     */
    isRightClickDisabled() {
      // Check for common right-click blocking
      const hasOnContextMenu = document.body?.getAttribute('oncontextmenu')?.includes('return false') ||
                               document.documentElement?.getAttribute('oncontextmenu')?.includes('return false');

      if (hasOnContextMenu) return true;

      // Check for event listeners (basic check)
      const scripts = document.querySelectorAll('script');
      for (const script of scripts) {
        const content = script.textContent || '';
        if (content.includes('contextmenu') && content.includes('preventDefault')) {
          return true;
        }
      }

      return false;
    }

    /**
     * Monitor forms for submission
     */
    monitorForms() {
      const forms = document.querySelectorAll('form');

      forms.forEach(form => {
        // Skip already monitored forms
        if (form.dataset.securityMonitored) return;
        form.dataset.securityMonitored = 'true';

        form.addEventListener('submit', (event) => {
          this.handleFormSubmit(event, form);
        });
      });
    }

    /**
     * Handle form submission
     * @param {Event} event - Submit event
     * @param {HTMLFormElement} form - Form element
     */
    async handleFormSubmit(event, form) {
      // Check if form has password field
      const hasPassword = form.querySelector('input[type="password"]');
      if (!hasPassword) return;

      try {
        const formAction = form.action || window.location.href;

        // Quick analysis of form action
        const response = await this.sendMessage('SECURITY_ANALYZE_URL', { url: formAction });

        if (response && response.threatScore >= 70) {
          // Block submission and warn user
          event.preventDefault();

          const proceed = await this.showInlineWarning(
            'This form may submit your credentials to a suspicious destination.',
            response
          );

          if (proceed) {
            form.submit();
          }
        }
      } catch (error) {
        console.warn('[Security Scanner] Form analysis error:', error);
      }
    }

    /**
     * Set up mutation observer for dynamic content
     */
    setupMutationObserver() {
      if (this.formObserver) return;

      this.formObserver = new MutationObserver((mutations) => {
        let shouldRescan = false;

        for (const mutation of mutations) {
          if (mutation.addedNodes.length > 0) {
            for (const node of mutation.addedNodes) {
              if (node.nodeType === Node.ELEMENT_NODE) {
                if (node.tagName === 'FORM' || node.querySelector?.('form')) {
                  shouldRescan = true;
                  break;
                }
                if (node.querySelector?.('input[type="password"]')) {
                  shouldRescan = true;
                  break;
                }
              }
            }
          }
          if (shouldRescan) break;
        }

        if (shouldRescan) {
          // Debounce rescan
          clearTimeout(this._rescanTimeout);
          this._rescanTimeout = setTimeout(() => {
            this.monitorForms();
          }, 500);
        }
      });

      this.formObserver.observe(document.body || document.documentElement, {
        childList: true,
        subtree: true
      });
    }

    /**
     * Handle messages from background script
     * @param {Object} message - Message object
     * @param {Object} sender - Sender info
     * @param {Function} sendResponse - Response callback
     */
    handleMessage(message, sender, sendResponse) {
      switch (message.type) {
        case 'SECURITY_SHOW_WARNING':
          this.showWarningOverlay(message.payload);
          sendResponse({ success: true });
          break;

        case 'SECURITY_REMOVE_WARNING':
          this.removeWarningOverlay();
          sendResponse({ success: true });
          break;

        case 'SECURITY_GET_PAGE_DATA':
          const pageData = this.collectPageData();
          sendResponse(pageData);
          break;

        default:
          sendResponse({ success: false, error: 'Unknown message type' });
      }
    }

    /**
     * Show warning overlay on page
     * @param {Object} payload - Warning payload with HTML and threatData
     */
    showWarningOverlay(payload) {
      if (this.warningDisplayed) return;

      try {
        // Create container
        this.warningOverlay = document.createElement('div');
        this.warningOverlay.id = 'cognitive-defense-security-overlay';
        this.warningOverlay.innerHTML = payload.html;

        // Add to page
        document.body.appendChild(this.warningOverlay);
        this.warningDisplayed = true;

        // Prevent scrolling
        document.body.style.overflow = 'hidden';

        // Add event listeners
        this.setupWarningEvents(payload.threatData);

        // Load custom CSS
        this.injectOverlayStyles();

      } catch (error) {
        console.error('[Security Scanner] Failed to show warning:', error);
      }
    }

    /**
     * Inject overlay styles
     */
    injectOverlayStyles() {
      if (document.getElementById('cognitive-defense-overlay-styles')) return;

      const link = document.createElement('link');
      link.id = 'cognitive-defense-overlay-styles';
      link.rel = 'stylesheet';
      link.href = chrome.runtime.getURL('content/threatOverlay.css');
      document.head.appendChild(link);
    }

    /**
     * Set up warning overlay event listeners
     * @param {Object} threatData - Threat data
     */
    setupWarningEvents(threatData) {
      // Go back button
      const goBackBtn = document.getElementById('security-go-back');
      if (goBackBtn) {
        goBackBtn.addEventListener('click', () => {
          // Go back in history or close tab
          if (window.history.length > 1) {
            window.history.back();
          } else {
            window.close();
          }
        });
      }

      // Proceed button (if exists)
      const proceedBtn = document.getElementById('security-proceed');
      if (proceedBtn) {
        proceedBtn.addEventListener('click', () => {
          // Add to whitelist temporarily and proceed
          this.sendMessage('SECURITY_WHITELIST_ADD', {
            domain: window.location.hostname
          });
          this.removeWarningOverlay();
        });
      }

      // ESC key to go back
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && this.warningDisplayed) {
          if (window.history.length > 1) {
            window.history.back();
          }
        }
      });
    }

    /**
     * Remove warning overlay
     */
    removeWarningOverlay() {
      if (this.warningOverlay) {
        this.warningOverlay.remove();
        this.warningOverlay = null;
        this.warningDisplayed = false;
        document.body.style.overflow = '';
      }
    }

    /**
     * Show inline warning for form submissions
     * @param {string} message - Warning message
     * @param {Object} threatData - Threat data
     * @returns {Promise<boolean>} Whether to proceed
     */
    showInlineWarning(message, threatData) {
      return new Promise((resolve) => {
        const confirmed = window.confirm(
          `⚠️ Security Warning\n\n${message}\n\n` +
          `Threat Score: ${threatData.threatScore}/100\n\n` +
          `Do you want to proceed anyway?`
        );
        resolve(confirmed);
      });
    }

    /**
     * Send message to background script
     * @param {string} type - Message type
     * @param {Object} payload - Message payload
     * @returns {Promise<any>} Response
     */
    sendMessage(type, payload) {
      return new Promise((resolve, reject) => {
        try {
          chrome.runtime.sendMessage({ type, payload }, (response) => {
            if (chrome.runtime.lastError) {
              console.warn('[Security Scanner] Message error:', chrome.runtime.lastError);
              resolve(null);
            } else {
              resolve(response);
            }
          });
        } catch (error) {
          console.warn('[Security Scanner] Message failed:', error);
          resolve(null);
        }
      });
    }

    /**
     * Clean up scanner
     */
    destroy() {
      if (this.formObserver) {
        this.formObserver.disconnect();
        this.formObserver = null;
      }
      this.removeWarningOverlay();
      this.initialized = false;
    }
  }

  // Initialize scanner
  const scanner = new SecurityScanner();

  // Cleanup on page unload
  window.addEventListener('unload', () => {
    scanner.destroy();
  });

})();
