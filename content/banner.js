/**
 * ScAIm Banner — Warning overlay injected at the top of suspicious pages.
 * Uses Shadow DOM to prevent page CSS from hiding or tampering with warnings.
 */
const ScaimBanner = {
  _bannerId: "scaim-banner",
  _spacerId: "scaim-spacer",
  _dismissedUrls: new Set(),

  // All banner styles embedded in Shadow DOM for isolation
  _styles: `
    :host {
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      right: 0 !important;
      z-index: 2147483647 !important;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 14px;
      line-height: 1.4;
      transform: translateY(-100%);
      transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1);
    }

    :host(.scaim-visible) {
      transform: translateY(0) !important;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    .scaim-inner {
      box-shadow: 0 2px 12px rgba(0, 0, 0, 0.15);
    }

    .scaim-inner.scaim-caution {
      background: linear-gradient(135deg, #FFF3CD, #FFEAA7);
      border-bottom: 3px solid #F0AD4E;
      color: #856404;
    }

    .scaim-inner.scaim-warning {
      background: linear-gradient(135deg, #FFE0CC, #FDCB6E);
      border-bottom: 3px solid #E67E22;
      color: #7D4E00;
    }

    .scaim-inner.scaim-danger {
      background: linear-gradient(135deg, #F8D7DA, #FF6B6B);
      border-bottom: 3px solid #DC3545;
      color: #721C24;
    }

    .scaim-banner-content {
      padding: 12px 16px;
      max-width: 1200px;
      margin: 0 auto;
    }

    .scaim-banner-header {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .scaim-banner-icon {
      font-size: 20px;
      flex-shrink: 0;
    }

    .scaim-banner-title {
      font-weight: 700;
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .scaim-banner-summary {
      flex: 1;
      font-size: 13px;
    }

    .scaim-banner-actions {
      display: flex;
      gap: 8px;
      flex-shrink: 0;
    }

    .scaim-banner-btn {
      border: none;
      padding: 5px 12px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
      font-weight: 600;
      font-family: inherit;
      transition: opacity 0.2s;
    }

    .scaim-banner-btn:hover {
      opacity: 0.8;
    }

    .scaim-btn-details {
      background: rgba(0, 0, 0, 0.1);
      color: inherit;
    }

    .scaim-btn-dismiss {
      background: rgba(0, 0, 0, 0.05);
      color: inherit;
    }

    .scaim-banner-findings {
      margin-top: 10px;
      padding-top: 10px;
      border-top: 1px solid rgba(0, 0, 0, 0.1);
      display: none;
    }

    .scaim-banner-findings.scaim-expanded {
      display: block;
    }

    .scaim-finding {
      padding: 6px 0;
      font-size: 13px;
      display: flex;
      align-items: flex-start;
      gap: 8px;
    }

    .scaim-finding + .scaim-finding {
      border-top: 1px solid rgba(0, 0, 0, 0.05);
    }

    .scaim-finding-severity {
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      padding: 2px 6px;
      border-radius: 3px;
      flex-shrink: 0;
      margin-top: 1px;
    }

    .scaim-severity-critical {
      background: #DC3545;
      color: white;
    }

    .scaim-severity-high {
      background: #E67E22;
      color: white;
    }

    .scaim-severity-medium {
      background: #F0AD4E;
      color: #7D4E00;
    }

    .scaim-severity-low {
      background: #6C757D;
      color: white;
    }

    .scaim-finding-text {
      flex: 1;
    }

    .scaim-finding-category {
      font-weight: 600;
      margin-right: 4px;
    }

    .scaim-privacy {
      margin-top: 8px;
      font-size: 11px;
      opacity: 0.7;
      font-style: italic;
    }

    .scaim-top-findings {
      margin-top: 8px;
      padding-left: 4px;
    }

    .scaim-top-finding {
      font-size: 13px;
      padding: 3px 0;
    }

    .scaim-top-finding::before {
      content: "\\26A0\\FE0F ";
    }

    .scaim-score-badge {
      font-weight: 700;
      font-size: 13px;
      padding: 2px 8px;
      border-radius: 10px;
      background: rgba(0, 0, 0, 0.1);
    }
  `,

  /**
   * Show the warning banner for the given assessment.
   * @param {{ level: string, score: number, summary: string, findings: Array }} assessment
   */
  show(assessment) {
    // In-memory dismissal check — immune to page script tampering
    if (this._dismissedUrls.has(window.location.href)) return;

    // Remove existing banner if any
    this.remove();

    const host = this._createBanner(assessment);
    const spacer = this._createSpacer();

    document.body.prepend(spacer);
    document.body.prepend(host);

    // Trigger slide-in animation
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        host.classList.add("scaim-visible");
        // Update spacer height after banner is visible
        setTimeout(() => {
          spacer.style.height = host.offsetHeight + "px";
          spacer.style.display = "block";
        }, 400);
      });
    });
  },

  /**
   * Remove the banner and spacer from the DOM.
   */
  remove() {
    const existing = document.getElementById(this._bannerId);
    if (existing) existing.remove();
    const spacer = document.getElementById(this._spacerId);
    if (spacer) spacer.remove();
  },

  /**
   * Create the banner DOM element with Shadow DOM isolation.
   */
  _createBanner(assessment) {
    const host = document.createElement("div");
    host.id = this._bannerId;

    // Closed shadow root — page JS cannot access internals
    const shadow = host.attachShadow({ mode: "closed" });

    // Inject styles into shadow
    const style = document.createElement("style");
    style.textContent = this._styles;
    shadow.appendChild(style);

    // Inner container with threat level class
    const inner = document.createElement("div");
    inner.className = `scaim-inner scaim-${assessment.level}`;

    const levelConfig = this._getLevelConfig(assessment.level);
    const topFindings = assessment.findings.slice(0, 3);

    inner.innerHTML = `
      <div class="scaim-banner-content">
        <div class="scaim-banner-header">
          <span class="scaim-banner-icon">${levelConfig.icon}</span>
          <span class="scaim-banner-title">${levelConfig.title}</span>
          <span class="scaim-score-badge">Score: ${assessment.score}/100</span>
          <span class="scaim-banner-summary">${this._escapeHtml(assessment.summary)}</span>
          <div class="scaim-banner-actions">
            <button class="scaim-banner-btn scaim-btn-details">
              Show all findings (${assessment.findings.length})
            </button>
            <button class="scaim-banner-btn scaim-btn-dismiss">
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

        <div class="scaim-banner-findings">
          ${assessment.findings.map(f => `
            <div class="scaim-finding">
              <span class="scaim-finding-severity scaim-severity-${f.severity}">${f.severity}</span>
              <span class="scaim-finding-text">
                <span class="scaim-finding-category">[${this._escapeHtml(f.category)}]</span>
                ${this._escapeHtml(f.message)}
              </span>
            </div>
          `).join("")}
          <div class="scaim-privacy">
            All analysis is performed locally in your browser. ScAIm does not collect, transmit, or log any of your personal data.
          </div>
        </div>
      </div>
    `;

    shadow.appendChild(inner);

    // Event listeners — query within shadow root
    const toggleBtn = shadow.querySelector(".scaim-btn-details");
    const findingsPanel = shadow.querySelector(".scaim-banner-findings");
    const dismissBtn = shadow.querySelector(".scaim-btn-dismiss");

    toggleBtn.addEventListener("click", () => {
      const isExpanded = findingsPanel.classList.toggle("scaim-expanded");
      toggleBtn.textContent = isExpanded
        ? "Hide findings"
        : `Show all findings (${assessment.findings.length})`;

      // Update spacer height
      setTimeout(() => {
        const spacer = document.getElementById(this._spacerId);
        if (spacer) spacer.style.height = host.offsetHeight + "px";
      }, 50);
    });

    dismissBtn.addEventListener("click", () => {
      host.classList.remove("scaim-visible");
      const spacer = document.getElementById(this._spacerId);
      if (spacer) spacer.style.display = "none";

      // In-memory dismissal — page scripts cannot access this
      this._dismissedUrls.add(window.location.href);

      setTimeout(() => this.remove(), 400);
    });

    return host;
  },

  /**
   * Create a spacer element to push page content down.
   */
  _createSpacer() {
    const spacer = document.createElement("div");
    spacer.id = this._spacerId;
    spacer.style.display = "none";
    return spacer;
  },

  /**
   * Get configuration for each threat level.
   */
  _getLevelConfig(level) {
    const configs = {
      caution: {
        icon: "\u26A0\uFE0F",
        title: "ScAIm \u2014 Caution"
      },
      warning: {
        icon: "\u{1F6A8}",
        title: "ScAIm \u2014 Warning"
      },
      danger: {
        icon: "\u{1F6D1}",
        title: "ScAIm \u2014 Danger"
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
