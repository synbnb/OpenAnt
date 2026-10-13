(() => {
  "use strict";

  // The navigation is data-driven and is mounted on every page that includes
  // this component. It is intentionally independent from the home page.
  const stages = [
    {
      id: "exposure",
      number: "01",
      zh: "设备暴露面发现",
      en: "Device exposure discovery",
      items: [
        { id: "assets-discovery", href: "/device-socket-assets", zh: "设备 Socket 资产发现", en: "Device socket asset discovery" },
        { id: "assets-history", href: "/device-socket-assets/history", zh: "设备 Socket 资产历史", en: "Device socket asset history" },
        { id: "exposure-locator", href: "/exposure-locator", zh: "暴露面识别与源码定位", en: "Exposure & source location" },
        { id: "exposure-history", href: "/exposure-locator?view=history", zh: "暴露面识别与定位历史", en: "Exposure & source location history" },
      ],
    },
    {
      id: "source",
      number: "02",
      zh: "暴露面识别与源码定位",
      en: "Exposure & source location",
      items: [
        { id: "source", href: "/source-locator", zh: "源码定位会话", en: "Source location sessions" },
      ],
    },
    {
      id: "static",
      number: "03",
      zh: "静态扫描",
      en: "Static scanning",
      items: [
        { id: "repository-manager", href: "/repository-manager", zh: "仓库管理", en: "Repository management" },
        { id: "vulnerability-summary", href: "/vulnerability-summary", zh: "漏洞汇总", en: "Vulnerability summary" },
        { id: "home", href: "/scan", hash: "new-scan-title", zh: "新建扫描", en: "New scan" },
        { id: "home", href: "/scan#recent-title", zh: "最近扫描与阶段产物", en: "Recent scans & artifacts" },
      ],
    },
    {
      id: "analysis",
      number: "04",
      zh: "动态测试",
      en: "Dynamic testing",
      items: [
        { id: "dynamic-test", href: "/dynamic-test", zh: "动态测试执行", en: "Dynamic test execution" },
        { id: "dynamic-history", href: "/dynamic-test-history", zh: "动态测试历史", en: "Dynamic test history" },
      ],
    },
    {
      id: "settings",
      number: "05",
      zh: "设置",
      en: "Settings",
      items: [
        { id: "settings", href: "/settings", zh: "大模型与运行设置", en: "Models & runtime settings" },
      ],
    },
  ];

  const language = () => (document.documentElement.lang || "zh").toLowerCase().startsWith("en") ? "en" : "zh";
  const overviewRoute = { href: "/" };

  const currentFromRoute = () => {
    const path = window.location.pathname;
    if (path === "/") return "dashboard";
    if (path.startsWith("/scan") || path.startsWith("/summary") || path.startsWith("/disclosure") || path.startsWith("/artifact")) return "home";
    if (path.startsWith("/repository-manager")) return "repository-manager";
    if (path.startsWith("/vulnerability-summary")) return "vulnerability-summary";
    if (path.startsWith("/device-socket-assets/history")) return "assets-history";
    if (path.startsWith("/device-socket-assets")) return "assets-discovery";
    if (path.startsWith("/exposure-locator")) return new URLSearchParams(window.location.search).get("view") === "history" ? "exposure-history" : "exposure-locator";
    if (path.startsWith("/exposure-surface")) return "exposure-locator";
    if (path.startsWith("/source-locator")) return "source";
    if (path.startsWith("/dynamic-test-history")) return "dynamic-history";
    if (path.startsWith("/dynamic-test")) return "dynamic-test";
    if (path.startsWith("/settings")) return "settings";
    return "";
  };

  class VulnFounderWorkspaceNav extends HTMLElement {
    connectedCallback() {
      this.openStages = new Set(["exposure", "source", "static", "analysis"]);
      this.mobileOpen = false;
      document.body.classList.add("vf-sidebar-page");
      this.onClick = event => this.handleClick(event);
      this.onToggle = event => {
        if (event.target?.matches?.(".workspace-sidebar-stage")) {
          if (event.target.open) this.openStages.add(event.target.dataset.stage);
          else this.openStages.delete(event.target.dataset.stage);
        }
      };
      this.onKeyDown = event => {
        if (event.key === "Escape" && this.mobileOpen) this.setMobileOpen(false);
      };
      this.addEventListener("click", this.onClick);
      this.addEventListener("toggle", this.onToggle, true);
      document.addEventListener("keydown", this.onKeyDown);
      this.render();
      this.languageObserver = new MutationObserver(() => this.render());
      this.languageObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["lang"] });
    }

    disconnectedCallback() {
      this.languageObserver?.disconnect();
      this.removeEventListener("click", this.onClick);
      this.removeEventListener("toggle", this.onToggle, true);
      document.removeEventListener("keydown", this.onKeyDown);
      document.body.classList.remove("vf-sidebar-page", "vf-sidebar-open");
    }

    handleClick(event) {
      const target = event.target.closest?.("[data-sidebar-toggle], [data-sidebar-close], .workspace-sidebar-backdrop, .workspace-sidebar-link, .workspace-sidebar-home");
      if (!target) return;
      if (target.matches("[data-sidebar-toggle]")) {
        this.setMobileOpen(!this.mobileOpen);
      } else if (target.matches("[data-sidebar-close], .workspace-sidebar-backdrop") || target.matches(".workspace-sidebar-link, .workspace-sidebar-home")) {
        this.setMobileOpen(false);
      }
    }

    setMobileOpen(open) {
      this.mobileOpen = Boolean(open);
      document.body.classList.toggle("vf-sidebar-open", this.mobileOpen);
      const toggle = this.querySelector("[data-sidebar-toggle]");
      toggle?.setAttribute("aria-expanded", String(this.mobileOpen));
    }

    render() {
      const lang = language();
      const explicitCurrent = this.getAttribute("current") || "";
      const current = explicitCurrent || currentFromRoute();
      const sidebarId = "vulnfounder-workspace-sidebar";
      const aside = document.createElement("aside");
      aside.id = sidebarId;
      aside.className = "workspace-sidebar";
      aside.setAttribute("aria-label", lang === "en" ? "VulnFounder workbench navigation" : "VulnFounder 工作台导航");

      const head = document.createElement("div");
      head.className = "workspace-sidebar-head";
      head.innerHTML = `<div class="workspace-sidebar-brand"><span class="workspace-sidebar-mark" aria-hidden="true">VF</span><span><strong>vulnfounder</strong><small>${lang === "en" ? "Security analysis workbench" : "安全分析工作台"}</small></span></div>`;
      const close = document.createElement("button");
      close.type = "button";
      close.className = "workspace-sidebar-close";
      close.dataset.sidebarClose = "";
      close.setAttribute("aria-label", lang === "en" ? "Close navigation" : "关闭导航");
      close.textContent = "×";
      head.appendChild(close);
      aside.appendChild(head);

      const overview = document.createElement("a");
      overview.className = "workspace-sidebar-home";
      overview.href = overviewRoute.href;
      overview.dataset.page = "dashboard";
      overview.innerHTML = `<span class="workspace-sidebar-home-icon" aria-hidden="true">⌂</span><span>${lang === "en" ? "Workbench overview" : "工作台总览"}</span><span class="workspace-sidebar-link-arrow" aria-hidden="true">→</span>`;
      if (current === "dashboard") overview.setAttribute("aria-current", "page");
      aside.appendChild(overview);

      const nav = document.createElement("nav");
      nav.className = "workspace-sidebar-nav";
      nav.setAttribute("aria-label", lang === "en" ? "Stages" : "分析阶段");
      for (const stage of stages) {
        const details = document.createElement("details");
        details.className = "workspace-sidebar-stage";
        details.dataset.stage = stage.id;
        details.open = this.openStages.has(stage.id) || stage.items.some(item => item.id === current);

        const summary = document.createElement("summary");
        summary.innerHTML = `<span class="workspace-sidebar-number">${stage.number}</span><span class="workspace-sidebar-stage-title">${stage[lang]}</span><span class="workspace-sidebar-chevron" aria-hidden="true">›</span>`;
        details.appendChild(summary);

        const links = document.createElement("div");
        links.className = "workspace-sidebar-links";
        for (const item of stage.items) {
          const link = document.createElement("a");
          link.className = "workspace-sidebar-link";
          link.href = item.hash ? `${item.href}#${item.hash}` : item.href;
          link.dataset.page = item.id;
          link.innerHTML = `<span class="workspace-sidebar-link-mark" aria-hidden="true"></span><span class="workspace-sidebar-link-label">${item[lang]}</span><span class="workspace-sidebar-link-arrow" aria-hidden="true">→</span>`;
          if (item.id === current) link.setAttribute("aria-current", "page");
          links.appendChild(link);
        }
        details.appendChild(links);
        nav.appendChild(details);
      }
      aside.appendChild(nav);

      const footer = document.createElement("div");
      footer.className = "workspace-sidebar-foot";
      footer.textContent = lang === "en" ? "Local workbench · evidence remains reviewable" : "本机工作台 · 每个阶段产物均可审阅";
      aside.appendChild(footer);

      const toggle = document.createElement("button");
      toggle.type = "button";
      toggle.className = "workspace-sidebar-toggle";
      toggle.dataset.sidebarToggle = "";
      toggle.setAttribute("aria-controls", sidebarId);
      toggle.setAttribute("aria-expanded", String(this.mobileOpen));
      toggle.setAttribute("aria-label", lang === "en" ? "Open workbench navigation" : "打开工作台导航");
      toggle.innerHTML = `<span aria-hidden="true">☰</span><span class="workspace-sidebar-toggle-text">${lang === "en" ? "Stages" : "阶段"}</span>`;

      const backdrop = document.createElement("div");
      backdrop.className = "workspace-sidebar-backdrop";
      backdrop.setAttribute("aria-hidden", "true");
      this.replaceChildren(aside, toggle, backdrop);
      this.setMobileOpen(this.mobileOpen);
    }
  }

  if (!customElements.get("vulnfounder-workspace-nav")) {
    customElements.define("vulnfounder-workspace-nav", VulnFounderWorkspaceNav);
  }
})();
