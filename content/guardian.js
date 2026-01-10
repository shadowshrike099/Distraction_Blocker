/* content/guardian.js - Time Guardian Overlay */

const QUOTES = [
    "The bitterest tears shed over graves are for words left unsaid and deeds left undone.",
    "Lost time is never found again.",
    "Your time is limited, so don't waste it living someone else's life.",
    "You may delay, but time will not.",
    "Time is the most valuable thing a man can spend.",
    "The bad news is time flies. The good news is you're the pilot.",
    "Don't be fooled by the calendar. There are only as many days in the year as you make use of.",
    "Determine never to be idle. No person will have occasion to complain of the want of time who never loses any.",
    "Time is what we want most, but what we use worst.",
    "A man who dares to waste one hour of time has not discovered the value of life.",
    "Procrastination is the thief of time.",
    "Time stays long enough for anyone who will use it.",
    "It is not that we have a short time to live, but that we waste a lot of it.",
    "Dost thou love life? Then do not squander time, for that's the stuff life is made of.",
    "Regret for wasted time is more wasted time."
];

let overlayElement = null;
let currentLimit = 0;
let currentTimeSpent = 0;
let currentDomain = '';

// Listen for messages
try {
    console.log('[Guardian Content] Listener ready');
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        console.log('[Guardian Content] Message received:', message);
        if (message.type === 'GUARDIAN_SHOW_OVERLAY') {
            const { timeSpent, limit, domain } = message.payload;
            currentLimit = limit;
            currentTimeSpent = timeSpent;
            currentDomain = domain;
            showOverlay();
        }
    });
} catch (e) {
    // Context invalidated, ignore
}

// Check on load if we should block
document.addEventListener('DOMContentLoaded', checkStatus);
window.addEventListener('load', checkStatus);
setInterval(checkStatus, 30000);

function checkStatus() {
    if (!chrome.runtime?.id) return; // Extension context invalidated

    const domain = window.location.hostname.replace('www.', '');

    // We send current hostname to background for verification
    try {
        console.log('[Guardian Content] Checking status for:', domain);
        chrome.runtime.sendMessage({
            type: 'GUARDIAN_CHECK_LIMIT',
            payload: { domain: findMatchingDomain(domain) }
        }, (response) => {
            if (chrome.runtime.lastError) return;
            console.log('[Guardian Content] Check response:', response);

            if (response && response.blocked) {
                currentLimit = response.limit;
                currentTimeSpent = response.timeSpent;
                currentDomain = findMatchingDomain(domain);
                showOverlay();
            }
        });
    } catch (e) {
        // Context invalidated
    }
}

function findMatchingDomain(hostname) {
    const SITES = ['facebook.com', 'instagram.com', 'tiktok.com', 'youtube.com', 'x.com', 'twitter.com', 'reddit.com', 'netflix.com'];
    return SITES.find(site => hostname.endsWith(site)) || hostname;
}

function showOverlay() {
    if (document.getElementById('cd-guardian-overlay')) return;

    overlayElement = document.createElement('div');
    overlayElement.id = 'cd-guardian-overlay';

    // Shadow DOM to isolate styles
    const shadow = overlayElement.attachShadow({ mode: 'open' });

    // Container
    const container = document.createElement('div');
    container.className = 'guardian-container';

    // Inline CSS for reliability
    const style = document.createElement('style');
    style.textContent = `
    :host { all: initial; }
    .guardian-container {
        position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
        background: rgba(5, 5, 10, 0.95); backdrop-filter: blur(20px);
        z-index: 2147483647; display: flex; justify-content: center; align-items: center;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        color: #ffffff; opacity: 0; animation: fadeInBackground 0.5s ease-out forwards;
    }
    @keyframes fadeInBackground { to { opacity: 1; } }
    .guardian-card {
        background: rgba(30, 30, 40, 0.7); border: 1px solid rgba(255, 255, 255, 0.1);
        box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.05), 0 25px 50px -12px rgba(0, 0, 0, 0.6), inset 0 0 20px rgba(255, 255, 255, 0.02);
        padding: 3.5rem; border-radius: 32px; text-align: center; max-width: 480px; width: 90%;
        transform: scale(0.95); opacity: 0; animation: popIn 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards 0.2s;
        position: relative; overflow: hidden;
    }
    .guardian-card::before {
        content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px;
        background: linear-gradient(90deg, #6366f1, #a855f7, #ec4899);
    }
    @keyframes popIn { to { transform: scale(1); opacity: 1; } }
    .guardian-icon {
        font-size: 3.5rem; margin-bottom: 1.5rem; display: inline-block;
        filter: drop-shadow(0 0 15px rgba(99, 102, 241, 0.3));
        animation: subtleFloat 4s ease-in-out infinite;
    }
    @keyframes subtleFloat { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-8px); } }
    h1 {
        font-size: 2.25rem; font-weight: 800; margin: 0 0 1rem 0; letter-spacing: -0.02em;
        background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%); background-clip: text;
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }
    .guardian-quote {
        font-size: 1.25rem; line-height: 1.6; color: #94a3b8; margin-bottom: 2.5rem;
        font-style: italic; font-weight: 300; border-left: 3px solid #6366f1; padding-left: 1.5rem; text-align: left;
    }
    .guardian-stats {
        display: flex; justify-content: center; align-items: center; gap: 1.5rem;
        background: rgba(0, 0, 0, 0.3); padding: 1rem 2rem; border-radius: 16px; margin-bottom: 2.5rem;
        font-size: 0.95rem; color: #94a3b8; border: 1px solid rgba(255, 255, 255, 0.05);
    }
    .guardian-stats strong { color: #e2e8f0; font-size: 1.2rem; font-weight: 600; font-feature-settings: "tnum"; }
    .divider { color: #475569; font-size: 1.2rem; }
    .guardian-action { display: flex; flex-direction: column; gap: 1.25rem; align-items: center; }
    .guardian-action p { margin: 0; font-size: 0.95rem; color: #a1a1aa; }
    input {
        background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(255, 255, 255, 0.1); color: white;
        padding: 1rem 1.5rem; border-radius: 12px; width: 100%; max-width: 240px; text-align: center;
        font-size: 1.1rem; letter-spacing: 0.05em; outline: none; transition: all 0.2s;
    }
    input:focus {
        border-color: #8b5cf6; background: rgba(0, 0, 0, 0.6); box-shadow: 0 0 0 4px rgba(139, 92, 246, 0.1);
    }
    .guardian-btn {
        background: linear-gradient(135deg, #4f46e5 0%, #4338ca 100%); color: #ffffff;
        border: none; padding: 1rem 2rem; border-radius: 12px; font-size: 1.05rem; font-weight: 600;
        cursor: pointer; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); width: 100%; max-width: 280px;
        position: relative; overflow: hidden;
    }
    .guardian-btn:disabled { background: #1e1e24; color: #52525b; cursor: not-allowed; opacity: 0.8; }
    .guardian-btn.active {
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); box-shadow: 0 10px 20px -5px rgba(99, 102, 241, 0.4);
    }
    .guardian-btn.active:hover { transform: translateY(-2px); box-shadow: 0 15px 25px -5px rgba(99, 102, 241, 0.5); }
    .countdown-timer { display: inline-flex; align-items: center; justify-content: center; font-variant-numeric: tabular-nums; }
    .shake { animation: shake 0.5s cubic-bezier(.36, .07, .19, .97) both; }
    @keyframes shake {
        10%, 90% { transform: translate3d(-1px, 0, 0); }
        20%, 80% { transform: translate3d(2px, 0, 0); }
        30%, 50%, 70% { transform: translate3d(-4px, 0, 0); }
        40%, 60% { transform: translate3d(4px, 0, 0); }
    }
    `;
    shadow.appendChild(style);

    // Quote
    const quote = QUOTES[Math.floor(Math.random() * QUOTES.length)];

    const minutesSpent = Math.floor(currentTimeSpent / 60);
    const limitMinutes = Math.floor(currentLimit / 60);

    container.innerHTML = `
        <div class="guardian-card">
            <div class="guardian-icon">⏳</div>
            <h1>Time Guardian</h1>
            <p class="guardian-quote">"${quote}"</p>
            <div class="guardian-stats">
                <span>Time Spent: <strong>${minutesSpent}m</strong></span>
                <span class="divider">/</span>
                <span>Daily Limit: <strong>${limitMinutes}m</strong></span>
            </div>
            
            <div class="guardian-action">
                <p>Type <strong>focus</strong> to continue</p>
                <input type="text" id="bypass-input" placeholder="type 'focus'" autocomplete="off" spellcheck="false">
                <button id="bypass-btn" class="guardian-btn" disabled>
                    Wait <span id="countdown" class="countdown-timer">15</span>s
                </button>
            </div>
        </div>
    `;

    shadow.appendChild(container);
    document.body.appendChild(overlayElement);
    document.body.style.overflow = 'hidden'; // Stop scrolling

    // Logic
    const input = shadow.getElementById('bypass-input');
    const btn = shadow.getElementById('bypass-btn');
    const countdownEl = shadow.getElementById('countdown');

    input.focus();

    // Countdown
    let timeLeft = 15;
    const interval = setInterval(() => {
        timeLeft--;
        if (timeLeft <= 0) {
            clearInterval(interval);
            btn.innerHTML = 'Continue';
            // Trigger check again in case they already typed it
            checkInput();
        } else {
            countdownEl.textContent = timeLeft;
        }
    }, 1000);

    // Input validation
    input.addEventListener('input', () => {
        checkInput();
    });

    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !btn.disabled) {
            btn.click();
        }
    });

    function checkInput() {
        if (timeLeft <= 0 && input.value.toLowerCase().trim() === 'focus') {
            btn.disabled = false;
            btn.classList.add('active');
        } else {
            btn.disabled = true;
            btn.classList.remove('active');
        }
    }

    // Bypass click
    btn.addEventListener('click', () => {
        if (!btn.disabled) {
            if (!chrome.runtime?.id) return;

            try {
                chrome.runtime.sendMessage({
                    type: 'GUARDIAN_BYPASS',
                    payload: { domain: currentDomain }
                }, (response) => {
                    if (chrome.runtime.lastError) return;
                    if (response && response.success) {
                        removeOverlay();
                    }
                });
            } catch (e) {
                // Context invalidated
                removeOverlay();
            }
        }
    });
}

function removeOverlay() {
    if (overlayElement) {
        overlayElement.remove();
        overlayElement = null;
        document.body.style.overflow = '';
    }
}
