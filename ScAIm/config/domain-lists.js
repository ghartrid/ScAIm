/**
 * ScAIm Domain Lists — Pre-shipped blocklist + user-managed allow/block lists.
 * Provides fast domain lookup for the analyzer to skip trusted sites
 * or auto-flag known-bad domains.
 */
const DomainLists = {
  // User lists are loaded from chrome.storage.local on init
  _userAllowlist: new Set(),
  _userBlocklist: new Set(),
  _loaded: false,

  /**
   * Pre-shipped blocklist of known scam domain patterns.
   * Each entry has a pattern (string or regex) and a category.
   * String patterns match as substrings of the hostname.
   * Regex patterns are tested against the full hostname.
   */
  BUILTIN_BLOCKLIST: [
    // Tech support scams
    { pattern: "microsoftsupport-help", category: "Tech Support Scam" },
    { pattern: "windows-error-fix", category: "Tech Support Scam" },
    { pattern: "apple-security-alert", category: "Tech Support Scam" },
    { pattern: "virus-removal-help", category: "Tech Support Scam" },
    { pattern: "pc-fix-now", category: "Tech Support Scam" },
    { pattern: "tech-support-help", category: "Tech Support Scam" },
    { pattern: "computer-fix-online", category: "Tech Support Scam" },
    { pattern: "geeksquad-renewal", category: "Tech Support Scam" },
    { pattern: "norton-renewal-alert", category: "Tech Support Scam" },
    { pattern: "mcafee-renewal-alert", category: "Tech Support Scam" },
    { pattern: "antivirus-renew", category: "Tech Support Scam" },
    { pattern: "security-alert-warning", category: "Tech Support Scam" },

    // Crypto scam patterns
    { pattern: "crypto-doubler", category: "Crypto Scam" },
    { pattern: "bitcoin-doubler", category: "Crypto Scam" },
    { pattern: "eth-giveaway", category: "Crypto Scam" },
    { pattern: "crypto-giveaway", category: "Crypto Scam" },
    { pattern: "free-bitcoin-mine", category: "Crypto Scam" },
    { pattern: "elonmusk-giveaway", category: "Crypto Scam" },
    { pattern: "tesla-token", category: "Crypto Scam" },
    { pattern: "metmask-", category: "Crypto Scam" },
    { pattern: "metamsk-", category: "Crypto Scam" },
    { pattern: "metamask-verify", category: "Crypto Scam" },
    { pattern: "metamask-update", category: "Crypto Scam" },
    { pattern: "trustwallet-verify", category: "Crypto Scam" },
    { pattern: "pancakeswap-airdrop", category: "Crypto Scam" },
    { pattern: "uniswap-airdrop", category: "Crypto Scam" },
    { pattern: "defi-yield-farm", category: "Crypto Scam" },

    // Phishing - brand impersonation
    { pattern: "paypal-verify-account", category: "Phishing" },
    { pattern: "paypal-secure-login", category: "Phishing" },
    { pattern: "amazon-verify-order", category: "Phishing" },
    { pattern: "amazon-security-alert", category: "Phishing" },
    { pattern: "netflix-update-payment", category: "Phishing" },
    { pattern: "netflix-billing-update", category: "Phishing" },
    { pattern: "apple-id-verify", category: "Phishing" },
    { pattern: "icloud-verify", category: "Phishing" },
    { pattern: "chase-verify-account", category: "Phishing" },
    { pattern: "wellsfargo-secure-login", category: "Phishing" },
    { pattern: "bankofamerica-alert", category: "Phishing" },
    { pattern: "usps-delivery-update", category: "Phishing" },
    { pattern: "fedex-delivery-notice", category: "Phishing" },
    { pattern: "dhl-tracking-update", category: "Phishing" },
    { pattern: "ups-delivery-confirm", category: "Phishing" },

    // Fake shopping sites (common patterns)
    { pattern: "super-deals-store", category: "Fake Shopping" },
    { pattern: "mega-discount-shop", category: "Fake Shopping" },
    { pattern: "cheap-brand-outlet", category: "Fake Shopping" },
    { pattern: "designer-replica-", category: "Fake Shopping" },
    { pattern: "luxury-outlet-sale", category: "Fake Shopping" },
    { pattern: "official-store-sale", category: "Fake Shopping" },

    // Survey/reward scams
    { pattern: "free-gift-survey", category: "Survey Scam" },
    { pattern: "prize-winner-claim", category: "Survey Scam" },
    { pattern: "reward-survey-now", category: "Survey Scam" },
    { pattern: "lucky-winner-today", category: "Survey Scam" },
    { pattern: "spin-wheel-prize", category: "Survey Scam" },

    // Fake download sites
    { pattern: "flash-player-update", category: "Fake Download" },
    { pattern: "java-update-required", category: "Fake Download" },
    { pattern: "browser-update-now", category: "Fake Download" },
    { pattern: "codec-download-free", category: "Fake Download" },
    { pattern: "font-download-missing", category: "Fake Download" },

    // Investment scam patterns
    { pattern: "guaranteed-returns-", category: "Investment Scam" },
    { pattern: "forex-profit-daily", category: "Investment Scam" },
    { pattern: "binary-option-profit", category: "Investment Scam" },
    { pattern: "passive-income-bot", category: "Investment Scam" },
    { pattern: "trading-bot-profit", category: "Investment Scam" },

    // Known suspicious TLD patterns (regex)
    { pattern: /^[a-z0-9-]+(paypal|amazon|apple|microsoft|google|netflix|chase|wellsfargo|bankofamerica)\.[a-z0-9-]+\.(xyz|top|club|buzz|tk|ml|ga|cf|gq|icu)$/i, category: "Phishing (Brand + Suspicious TLD)" },
    { pattern: /^(login|secure|verify|update|account|billing|confirm)-?[a-z0-9-]+\.(xyz|top|club|buzz|tk|ml|ga|cf|gq|icu)$/i, category: "Phishing (Credential Harvesting TLD)" }
  ],

  /**
   * Initialize domain lists from chrome.storage.local.
   * @returns {Promise}
   */
  async init() {
    if (this._loaded) return;

    return new Promise((resolve) => {
      try {
        chrome.storage.local.get(["scaim_allowlist", "scaim_blocklist"], (result) => {
          if (result.scaim_allowlist) {
            this._userAllowlist = new Set(result.scaim_allowlist);
          }
          if (result.scaim_blocklist) {
            this._userBlocklist = new Set(result.scaim_blocklist);
          }
          this._loaded = true;
          resolve();
        });
      } catch (e) {
        // Extension context may be invalidated
        this._loaded = true;
        resolve();
      }
    });
  },

  /**
   * Check if a hostname is on the user's allowlist.
   * @param {string} hostname
   * @returns {boolean}
   */
  isAllowed(hostname) {
    hostname = hostname.toLowerCase();
    // Check exact match and parent domain
    if (this._userAllowlist.has(hostname)) return true;
    // Check if a parent domain is allowed (e.g., "example.com" allows "sub.example.com")
    const parts = hostname.split(".");
    for (let i = 1; i < parts.length - 1; i++) {
      const parent = parts.slice(i).join(".");
      if (this._userAllowlist.has(parent)) return true;
    }
    return false;
  },

  /**
   * Check if a hostname is on any blocklist (built-in or user).
   * Returns the match info or null.
   * @param {string} hostname
   * @returns {{ source: string, category: string } | null}
   */
  isBlocked(hostname) {
    hostname = hostname.toLowerCase();

    // Check user blocklist first (exact match)
    if (this._userBlocklist.has(hostname)) {
      return { source: "user", category: "User Blocklist" };
    }

    // Check built-in blocklist
    for (const entry of this.BUILTIN_BLOCKLIST) {
      if (entry.pattern instanceof RegExp) {
        if (entry.pattern.test(hostname)) {
          return { source: "builtin", category: entry.category };
        }
      } else {
        if (hostname.includes(entry.pattern)) {
          return { source: "builtin", category: entry.category };
        }
      }
    }

    return null;
  },

  /**
   * Add a domain to the user allowlist.
   * @param {string} hostname
   */
  async addToAllowlist(hostname) {
    hostname = hostname.toLowerCase();
    this._userAllowlist.add(hostname);
    // Remove from blocklist if present
    this._userBlocklist.delete(hostname);
    await this._persist();
  },

  /**
   * Remove a domain from the user allowlist.
   * @param {string} hostname
   */
  async removeFromAllowlist(hostname) {
    hostname = hostname.toLowerCase();
    this._userAllowlist.delete(hostname);
    await this._persist();
  },

  /**
   * Add a domain to the user blocklist.
   * @param {string} hostname
   */
  async addToBlocklist(hostname) {
    hostname = hostname.toLowerCase();
    this._userBlocklist.add(hostname);
    // Remove from allowlist if present
    this._userAllowlist.delete(hostname);
    await this._persist();
  },

  /**
   * Remove a domain from the user blocklist.
   * @param {string} hostname
   */
  async removeFromBlocklist(hostname) {
    hostname = hostname.toLowerCase();
    this._userBlocklist.delete(hostname);
    await this._persist();
  },

  /**
   * Get the current user lists (for popup display).
   * @returns {{ allowlist: string[], blocklist: string[] }}
   */
  getLists() {
    return {
      allowlist: [...this._userAllowlist].sort(),
      blocklist: [...this._userBlocklist].sort()
    };
  },

  /**
   * Persist user lists to chrome.storage.local.
   */
  async _persist() {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.set({
          scaim_allowlist: [...this._userAllowlist],
          scaim_blocklist: [...this._userBlocklist]
        }, resolve);
      } catch (e) {
        resolve();
      }
    });
  }
};
