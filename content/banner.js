/**
 * ScAIm Banner — Warning overlay injected at the top of suspicious pages.
 */
const ScaimBanner = {
  _bannerId: "scaim-banner",
  _dismissedUrls: new Set(),
  _removeTimer: null,

  /**
   * Show the warning banner for the given assessment.
   * @param {{ level: string, score: number, summary: string, findings: Array }} assessment
   */
  show(assessment) {
    // Check if dismissed for this page this session (in-memory only —
    // sessionStorage is shared with host page and can be exploited to suppress banners)
    if (this._dismissedUrls.has(window.location.href)) return;

    // Cancel any pending remove timer (prevents stale dismiss/trust setTimeout
    // from removing a newly-shown banner during the 400ms fade-out window)
    clearTimeout(this._removeTimer);

    // Remove existing banner if any
    this.remove();

    const banner = this._createBanner(assessment);

    document.body.prepend(banner);

    // Trigger slide-in animation
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        banner.classList.add("scaim-visible");
      });
    });
  },

  /**
   * Show a compact lite banner that auto-hides after 5 seconds.
   */
  showLite(assessment) {
    if (this._dismissedUrls.has(window.location.href)) return;
    clearTimeout(this._removeTimer);
    this.remove();

    const levelConfig = this._getLevelConfig(assessment.level);
    const banner = document.createElement("div");
    banner.id = this._bannerId;
    banner.className = `scaim-banner-lite scaim-${assessment.level}`;

    const content = document.createElement("div");
    content.className = "scaim-lite-content";

    const icon = document.createElement("span");
    icon.className = "scaim-lite-icon";
    icon.textContent = levelConfig.icon;

    const text = document.createElement("span");
    text.className = "scaim-lite-text";
    text.textContent = levelConfig.title + " \u2014 Score: " + assessment.score + "/100";

    const dismissBtn = document.createElement("button");
    dismissBtn.className = "scaim-lite-dismiss";
    dismissBtn.title = "Dismiss";
    dismissBtn.textContent = "\u00D7";

    content.appendChild(icon);
    content.appendChild(text);
    content.appendChild(dismissBtn);
    banner.appendChild(content);
    dismissBtn.addEventListener("click", () => {
      clearTimeout(this._removeTimer);
      banner.classList.remove("scaim-visible");
      this._dismissedUrls.add(window.location.href);
      this._removeTimer = setTimeout(() => this.remove(), 400);
    });

    document.body.prepend(banner);

    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        banner.classList.add("scaim-visible");
      });
    });

    // Auto-hide after 5 seconds
    this._removeTimer = setTimeout(() => {
      if (document.getElementById(this._bannerId)) {
        banner.classList.remove("scaim-visible");
        this._removeTimer = setTimeout(() => this.remove(), 400);
      }
    }, 5000);
  },

  /**
   * Remove the banner and spacer from the DOM.
   */
  remove() {
    const existing = document.getElementById(this._bannerId);
    if (existing) existing.remove();
  },

  /**
   * Create the banner DOM element.
   */
  _createBanner(assessment) {
    const banner = document.createElement("div");
    banner.id = this._bannerId;
    banner.className = `scaim-${assessment.level}`;

    const levelConfig = this._getLevelConfig(assessment.level);
    const topFindings = assessment.findings.slice(0, 3);
    const VALID_SEV = ["critical", "high", "medium", "low"];

    banner.innerHTML = `
      <div class="scaim-banner-content">
        <div class="scaim-banner-header">
          <span class="scaim-banner-icon">${levelConfig.icon}</span>
          <span class="scaim-banner-title">${levelConfig.title}</span>
          <span class="scaim-score-badge">Score: ${assessment.score}/100</span>
          <span class="scaim-banner-summary">${this._escapeHtml(assessment.summary)}</span>
          <div class="scaim-banner-actions">
            <button class="scaim-banner-btn scaim-btn-details" id="scaim-toggle-details">
              Show all findings (${assessment.findings.length})
            </button>
            <button class="scaim-banner-btn scaim-btn-trust" id="scaim-trust" title="Add this site to your trusted allowlist">
              Trust this site
            </button>
            <button class="scaim-banner-btn scaim-btn-dismiss" id="scaim-dismiss">
              Dismiss
            </button>
          </div>
        </div>

        ${topFindings.length > 0 ? `
          <div class="scaim-top-findings">
            ${topFindings.map(f => `
              <div class="scaim-top-finding">${this._escapeHtml(f.message)}</div>
            `).join("")}
          </div>
        ` : ""}

        <div class="scaim-banner-findings" id="scaim-findings">
          ${assessment.findings.map(f => {
            const sev = VALID_SEV.includes(f.severity) ? f.severity : "medium";
            return `
            <div class="scaim-finding">
              <span class="scaim-finding-severity scaim-severity-${sev}">${sev}</span>
              <span class="scaim-finding-text">
                <span class="scaim-finding-category">[${this._escapeHtml(f.category)}]</span>
                ${this._escapeHtml(f.message)}
              </span>
            </div>
          `;}).join("")}
          <div class="scaim-privacy">
            All analysis is performed locally in your browser. ScAIm does not collect, transmit, or log any of your personal data.
          </div>
        </div>
      </div>
    `;

    // Event listeners
    const toggleBtn = banner.querySelector("#scaim-toggle-details");
    const findingsPanel = banner.querySelector("#scaim-findings");
    const dismissBtn = banner.querySelector("#scaim-dismiss");

    toggleBtn.addEventListener("click", () => {
      const isExpanded = findingsPanel.classList.toggle("scaim-expanded");
      toggleBtn.textContent = isExpanded
        ? "Hide findings"
        : `Show all findings (${assessment.findings.length})`;
    });

    const trustBtn = banner.querySelector("#scaim-trust");
    trustBtn.addEventListener("click", () => {
      const hostname = window.location.hostname;
      // Update content script's in-memory allowlist directly so rerun() recognizes it
      if (typeof DomainLists !== "undefined") {
        DomainLists.addToAllowlist(hostname);
      }
      // Also persist via background service worker
      try {
        chrome.runtime.sendMessage({
          type: "SCAIM_ALLOWLIST_ADD",
          hostname: hostname
        });
      } catch (e) { /* ignore */ }
      // Remove banner immediately
      banner.classList.remove("scaim-visible");
      ScaimBanner._removeTimer = setTimeout(() => this.remove(), 400);
    });

    dismissBtn.addEventListener("click", () => {
      banner.classList.remove("scaim-visible");

      // Remember dismissal for this page (in-memory, inaccessible to host page)
      ScaimBanner._dismissedUrls.add(window.location.href);

      ScaimBanner._removeTimer = setTimeout(() => this.remove(), 400);
    });

    return banner;
  },

  /**
   * Get configuration for each threat level.
   */
  _getLevelConfig(level) {
    const configs = {
      caution: {
        icon: "\u26A0\uFE0F",
        title: "ScAIm — Caution"
      },
      warning: {
        icon: "\u{1F6A8}",
        title: "ScAIm — Warning"
      },
      danger: {
        icon: "\u{1F6D1}",
        title: "ScAIm — Danger"
      }
    };
    return configs[level] || configs.caution;
  },

  /**
   * Escape HTML to prevent XSS from page content appearing in findings.
   */
  _escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  }
};
