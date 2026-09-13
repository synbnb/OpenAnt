(() => {
  "use strict";

  const destinations = [
    { id: "home", href: "/", zh: "扫描工作台", en: "Scan workspace" },
    { id: "exposure", href: "/exposure-locator", zh: "暴露面与定位", en: "Exposure & location" },
    { id: "assets", href: "/device-socket-assets#asset-history", zh: "设备资产历史", en: "Device asset history" },
    { id: "source", href: "/source-locator", zh: "源码定位", en: "Source location" },
    { id: "scope", href: "/socket-scope", zh: "扫描范围", en: "Scan scope" },
  ];

  const language = () => document.documentElement.lang.toLowerCase().startsWith("en") ? "en" : "zh";

  class VulnFounderWorkspaceNav extends HTMLElement {
    connectedCallback() {
      this.render();
      this.languageObserver = new MutationObserver(() => this.render());
      this.languageObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["lang"] });
      this.onDocumentClick = event => {
        if (!this.contains(event.target)) this.querySelector("details")?.removeAttribute("open");
      };
      this.onKeyDown = event => {
        if (event.key === "Escape") {
          const menu = this.querySelector("details");
          if (menu?.open) {
            menu.open = false;
            menu.querySelector("summary")?.focus();
          }
        }
      };
      document.addEventListener("click", this.onDocumentClick);
      this.addEventListener("keydown", this.onKeyDown);
    }

    disconnectedCallback() {
      this.languageObserver?.disconnect();
      document.removeEventListener("click", this.onDocumentClick);
      this.removeEventListener("keydown", this.onKeyDown);
    }

    render() {
      const lang = language();
      const current = this.getAttribute("current") || "";
      const wasOpen = this.querySelector("details")?.open || false;
      const details = document.createElement("details");
      details.className = "workspace-menu";
      details.open = wasOpen;

      const summary = document.createElement("summary");
      summary.textContent = lang === "en" ? "Stage navigation" : "阶段导航";
      details.appendChild(summary);

      const nav = document.createElement("nav");
      nav.className = "workspace-menu-panel";
      nav.setAttribute("aria-label", lang === "en" ? "VulnFounder workspaces" : "VulnFounder 工作台导航");
      for (const destination of destinations) {
        const link = document.createElement("a");
        link.className = "workspace-menu-link";
        link.href = destination.href;
        link.textContent = destination[lang];
        if (destination.id === current) {
          link.setAttribute("aria-current", "page");
          const marker = document.createElement("span");
          marker.className = "workspace-menu-current";
          marker.textContent = lang === "en" ? "Current" : "当前";
          link.appendChild(marker);
        }
        link.addEventListener("click", () => { details.open = false; });
        nav.appendChild(link);
      }
      details.appendChild(nav);
      this.replaceChildren(details);
    }
  }

  if (!customElements.get("vulnfounder-workspace-nav")) {
    customElements.define("vulnfounder-workspace-nav", VulnFounderWorkspaceNav);
  }
})();
