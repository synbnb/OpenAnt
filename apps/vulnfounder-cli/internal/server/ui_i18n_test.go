package server

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	uifiles "vulnfounder/apps/vulnfounder-cli/ui"
)

func readUITemplate(t *testing.T, name string) string {
	t.Helper()
	data, err := uifiles.FS.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

func TestWebTemplatesParseAfterRedesign(t *testing.T) {
	for _, name := range []string{
		"dashboard.html",
		"index.html",
		"repository-manager.html",
		"vulnerability-summary.html",
		"scan.html",
		"artifact-view.html",
		"source-locator.html",
		"exposure-surface.html",
		"exposure-locator.html",
		"device-socket-assets.html",
		"device-socket-asset-history.html",
		"socket-scope.html",
		"settings.html",
		"dynamic-test.html",
		"dynamic-test-history.html",
		"summary.html",
		"disclosure.html",
	} {
		if _, err := template.ParseFS(uifiles.FS, name); err != nil {
			t.Errorf("parse %s: %v", name, err)
		}
	}
}

func TestRepositoryManagementHasIndependentPage(t *testing.T) {
	body := readUITemplate(t, "repository-manager.html")
	for _, want := range []string{
		"id=\"repository-manager-title\"",
		"id=\"repository-archive\"",
		"id=\"repository-upload-button\"",
		"id=\"repository-manager-list\"",
		"/api/repositories",
		"async function remove",
		"source_code_base",
		"上传 ZIP",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("repository-manager.html missing repository-management marker %q", want)
		}
	}
	if strings.Contains(readUITemplate(t, "index.html"), `id="repository-manager-title"`) {
		t.Fatal("index.html still renders the repository manager panel")
	}
}

func TestVulnerabilitySummaryTemplateProvidesFilters(t *testing.T) {
	body := readUITemplate(t, "vulnerability-summary.html")
	for _, want := range []string{"/api/vulnerabilities", "summary-repository", "summary-scan", "summary-type", "summary-classification", "value=\"vulnerable\"", "value=\"inconclusive\"", "summary-function", "scan_sessions", "查看披露报告"} {
		if !strings.Contains(body, want) {
			t.Errorf("vulnerability-summary.html missing marker %q", want)
		}
	}
}

func TestDynamicTestDeliverablesAreMountedBeforeSourcePreview(t *testing.T) {
	body := readUITemplate(t, "dynamic-test.html")
	quick := strings.Index(body, "const quickNames")
	mount := strings.Index(body[quick:], "body.appendChild(s);")
	if mount >= 0 {
		mount += quick
	}
	preview := strings.Index(body, "await renderSourceExplorer(runId")
	if quick < 0 || mount < 0 || preview < 0 {
		t.Fatalf("dynamic-test.html is missing the deliverable/source preview markers")
	}
	if mount > preview {
		t.Fatalf("deliverable card is mounted only after the slow source preview")
	}
}

func TestWebTemplatesUseSharedVisualLanguage(t *testing.T) {
	for _, name := range []string{
		"dashboard.html",
		"index.html",
		"repository-manager.html",
		"vulnerability-summary.html",
		"scan.html",
		"artifact-view.html",
		"source-locator.html",
		"exposure-surface.html",
		"exposure-locator.html",
		"device-socket-assets.html",
		"device-socket-asset-history.html",
		"socket-scope.html",
		"settings.html",
		"dynamic-test.html",
		"dynamic-test-history.html",
		"summary.html",
		"disclosure.html",
	} {
		body := readUITemplate(t, name)
		if !strings.Contains(body, `href="/assets/vulnfounder-theme.css"`) {
			t.Errorf("%s does not load the shared VulnFounder theme", name)
		}
	}

	theme := readUITemplate(t, "vulnfounder-theme.css")
	for _, want := range []string{
		"--oa-canvas:",
		"--oa-accent:",
		".device-assets-page",
		".socket-scope-page",
		".report-reader-page",
		"@media (prefers-reduced-motion: reduce)",
	} {
		if !strings.Contains(theme, want) {
			t.Errorf("vulnfounder-theme.css missing design-system marker %q", want)
		}
	}
}

func TestSharedThemeAssetIsServedAsCSS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/assets/vulnfounder-theme.css", nil)
	req.SetPathValue("name", "vulnfounder-theme.css")
	rec := httptest.NewRecorder()

	(&Server{}).handleAsset(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("theme status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/css; charset=utf-8" {
		t.Fatalf("theme content type = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("theme cache control = %q", got)
	}
	if !strings.Contains(rec.Body.String(), "VulnFounder shared visual language") {
		t.Fatal("theme response does not contain the shared stylesheet")
	}
}

func TestWorkbenchTemplatesUseSharedStageNavigation(t *testing.T) {
	for _, name := range []string{
		"dashboard.html",
		"index.html",
		"repository-manager.html",
		"vulnerability-summary.html",
		"scan.html",
		"artifact-view.html",
		"source-locator.html",
		"exposure-surface.html",
		"exposure-locator.html",
		"device-socket-assets.html",
		"device-socket-asset-history.html",
		"socket-scope.html",
		"summary.html",
		"disclosure.html",
	} {
		body := readUITemplate(t, name)
		for _, want := range []string{
			`src="/assets/vulnfounder-navigation.js"`,
			"<vulnfounder-workspace-nav",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s missing shared navigation marker %q", name, want)
			}
		}
	}

	navigation := readUITemplate(t, "vulnfounder-navigation.js")
	for _, want := range []string{
		`href: "/"`,
		`href: "/exposure-locator"`,
		`href: "/device-socket-assets/history"`,
		`href: "/source-locator"`,
		`href: "/dynamic-test"`,
		`href: "/dynamic-test-history"`,
		`href: "/repository-manager"`,
		`href: "/vulnerability-summary"`,
		`link.setAttribute("aria-current", "page")`,
		`event.key === "Escape"`,
	} {
		if !strings.Contains(navigation, want) {
			t.Errorf("vulnfounder-navigation.js missing navigation behavior %q", want)
		}
	}
}

func TestSharedNavigationAssetIsServedAsJavaScript(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/assets/vulnfounder-navigation.js", nil)
	req.SetPathValue("name", "vulnfounder-navigation.js")
	rec := httptest.NewRecorder()

	(&Server{}).handleAsset(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("navigation status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/javascript; charset=utf-8" {
		t.Fatalf("navigation content type = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("navigation cache control = %q", got)
	}
	if !strings.Contains(rec.Body.String(), "VulnFounderWorkspaceNav") {
		t.Fatal("navigation response does not contain the shared component")
	}
}

func TestSocketScopeTemplateProvidesDiscoveryAndConfirmationControls(t *testing.T) {
	body := readUITemplate(t, "socket-scope.html")
	for _, want := range []string{
		"{{.CSRF}}",
		"/socket-scope/discover",
		"/socket-scope/select",
		"scan_scope.json",
		"candidate_id",
		"服务端收包",
		"确认并用于普通扫描",
		"textContent",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("socket-scope.html missing interactive marker %q", want)
		}
	}
}

func TestSourceLocatorTemplateProvidesInteractiveSessionWorkbench(t *testing.T) {
	body := readUITemplate(t, "source-locator.html")
	for _, want := range []string{
		"{{.CSRF}}",
		"/source-locator/sessions",
		"/advance",
		"/approve",
		"/select-version",
		"/reject",
		"/cancel",
		"EventSource",
		"/events/snapshot",
		"X-CSRF-Token",
		"id=\"artifacts\"",
		"id=\"events\"",
		"id=\"llm-search\"",
		"id=\"llm-round-limit\"",
		"id=\"batch-targets\"",
		"id=\"batch-create\"",
		"id=\"batch-progress\"",
		"runBatch",
		"At most 32 targets",
		"id=\"evidence-modal\"",
		"showLLMEvidence",
		"llm.evidenceDetail",
		"id=\"search-insights\"",
		"id=\"search-metrics\"",
		"id=\"search-graph\"",
		"id=\"search-evidence-list\"",
		"id=\"version-selection\"",
		"id=\"version-candidates\"",
		"versionChosenRevision",
		"searchGraphZoom",
		"searchEvidenceFilter",
		"searchView.graphTitle",
		"deriveServiceTopology",
		"renderServiceTopology",
		"topology-viewport",
		"confirm-role-source",
		"source_evidence",
		"hydrateConfirmationEvidence",
		"Internal verification files are not rendered as topology nodes.",
		"fetchSearchArtifact",
		"action.help",
		"minmax(260px,280px)",
		"aria-busy",
		"notice.running",
		"llm.search.round",
		"本次定位会话最多轮数",
		"Maximum rounds for this locator session",
		"1–40",
		"隐藏思维链",
		"textContent",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("source-locator.html missing interactive marker %q", want)
		}
	}
}

func TestWebTemplatesUseChineseOnlyChrome(t *testing.T) {
	for _, name := range []string{"dashboard.html", "index.html", "scan.html", "artifact-view.html", "source-locator.html", "exposure-surface.html", "device-socket-assets.html", "device-socket-asset-history.html", "settings.html"} {
		body := readUITemplate(t, name)
		if strings.Contains(body, "<option value=\"en\">English</option>") {
			t.Errorf("%s still exposes the English language selector", name)
		}
		if strings.Contains(body, "<div class=\"language-field\"") || strings.Contains(body, "<label for=\"language-select\"") {
			t.Errorf("%s still exposes a visible language switcher", name)
		}
		if !strings.Contains(body, "vulnfounder-workspace-nav") || !strings.Contains(body, "lang=\"zh-CN\"") {
			t.Errorf("%s must keep the shared navigation and Chinese locale", name)
		}
	}
}

func TestSettingsTemplateProvidesCentralizedModelManagement(t *testing.T) {
	body := readUITemplate(t, "settings.html")
	for _, want := range []string{
		"/settings/llm",
		"/settings/llm/configs",
		"/settings/llm/default",
		"模型配置已保存",
		"API Key 仅写入本机配置文件",
		"deleteConfig",
		"setDefault",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("settings.html missing model-management marker %q", want)
		}
	}
}

func TestExposureSurfaceTemplateProvidesStandaloneWorkbench(t *testing.T) {
	body := readUITemplate(t, "exposure-surface.html")
	for _, want := range []string{
		"/exposure-surface/sessions",
		"/events/snapshot",
		"/artifact/",
		"EventSource",
		"X-CSRF-Token",
		"id=\"create-form\"",
		"id=\"batch-targets\"",
		"id=\"batch-create\"",
		"id=\"batch-progress\"",
		"runBatch",
		"history-group",
		"history-group-select",
		"history.batchGroup",
		"batch_id",
		"At most 32 targets",
		"id=\"surfaces\"",
		"id=\"events\"",
		"id=\"artifacts\"",
		"id=\"start-confirmation\"",
		"id=\"start-service-btn\"",
		"id=\"skip-service-btn\"",
		"/start-service",
		"/skip-start",
		"textContent",
		"只读探测",
		"@media (max-width: 640px)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposure-surface.html missing interactive marker %q", want)
		}
	}
}

func TestDeviceSocketAssetsTemplateProvidesAgenticInventoryControls(t *testing.T) {
	body := readUITemplate(t, "device-socket-assets.html")
	for _, want := range []string{
		"设备 Socket 资产发现",
		"{{.CSRF}}",
		"/device-socket-assets/scan",
		"/device-socket-assets/snapshots",
		"finish_inventory",
		"动态选择",
		"只读",
		"device_serial",
		"observed_socket_records",
		"全部 Socket 实例（原始枚举）",
		"socket-record-search",
		"socket-record-prev",
		"本轮运行产物",
		"renderSocketRecordsWithState",
		"socket_record_summary",
		"textContent",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("device-socket-assets.html missing interactive marker %q", want)
		}
	}
}

func TestDeviceSocketAssetHistoryIsAStandalonePage(t *testing.T) {
	body := readUITemplate(t, "device-socket-asset-history.html")
	for _, want := range []string{
		"设备 Socket 资产历史",
		"/device-socket-assets/runs",
		"/device-socket-assets/snapshots",
		"run-history",
		"snapshot-history",
		"/device-socket-assets?run=",
		"/device-socket-assets?snapshot=",
		"vulnfounder-workspace-nav",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("device-socket-asset-history.html missing marker %q", want)
		}
	}
}

func TestExposureLocatorProvidesAssetHistoryTargetPicker(t *testing.T) {
	body := readUITemplate(t, "exposure-locator.html")
	for _, want := range []string{
		"从设备 Socket 资产历史选择目标",
		"asset-target-list",
		"asset-target-filter",
		"asset-target-selection",
		"asset-run-list",
		"asset-run-status",
		"/device-socket-assets/asset-options",
		"/device-socket-assets/runs",
		"刷新历史资产",
		"继续手动输入",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposure-locator.html missing asset picker marker %q", want)
		}
	}
}

func TestExposureLocatorKeepsLiveLLMRoundsAndSelectsCurrentSession(t *testing.T) {
	body := readUITemplate(t, "exposure-locator.html")
	for _, want := range []string{
		"upsertLocatorRound",
		"state.locatorEvents.map(locatorRoundFromEvent)",
		"id=\"locator-llm-round-limit\"",
		"if(item.type === \"llm.search.round\")renderLocatorLLM()",
		"function historyActive(item)",
		"state.history.find(historyActive)",
		"url.searchParams.set(\"locator_id\"",
		"state.exposure={...state.exposure,state:item.state}",
		"state.locator={...state.locator,state:item.state}",
		"renderLocator(state.locator);}renderEvents(\"locator-events\",state.locatorEvents);",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposure-locator.html missing live-session audit marker %q", want)
		}
	}
	if strings.Count(body, `id="locator-llm-rounds"`) != 1 {
		t.Errorf("exposure-locator.html must have exactly one LLM round container id")
	}
}

func TestExposureLocatorRendersReadableExposureArtifacts(t *testing.T) {
	body := readUITemplate(t, "exposure-locator.html")
	for _, want := range []string{
		"阶段 1 产物与证据",
		"查看易读摘要",
		"查看原文",
		"exposure_commands.jsonl",
		"设备命令记录",
		"设备证据条目",
		"Agent 任务计划",
		"function formatExposureArtifact",
		"function parseArtifactContent",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposure-locator.html missing readable artifact marker %q", want)
		}
	}
}

func TestWebRedesignKeepsCoreScanControlsAndResponsiveStates(t *testing.T) {
	index := readUITemplate(t, "index.html")
	for _, want := range []string{
		"method=\"POST\" action=\"/scan\"",
		"name=\"csrf\"",
		"name=\"repo_id\"",
		"name=\"repo\"",
		"name=\"platform\"",
		"name=\"level\"",
		"模型配置已集中到左侧“设置”页面",
		"name=\"verify\"",
		"name=\"no_context\"",
		"name=\"no_enhance\"",
		"name=\"enhance_mode\"",
		"name=\"no_report\"",
		"name=\"no_skip_tests\"",
		"name=\"all_languages\"",
		"name=\"multi_language\"",
		"name=\"strict_languages\"",
		"name=\"min_language_files\"",
		"name=\"min_language_share\"",
		"name=\"limit\"",
		"name=\"workers\"",
		"name=\"backoff\"",
		"name=\"library_mode\"",
		"name=\"llm_reachability\"",
		"name=\"llm_reachability_max_code_bytes\"",
		"name=\"llm_call_graph_recovery\"",
		"name=\"llm_call_graph_iterative_recovery\"",
		"name=\"llm_call_graph_candidate_review\"",
		"name=\"llm_call_graph_projection\"",
		"name=\"openharmony_dispatch_code_evidence\"",
		"reachability-value",
		"scan.llmReachabilityBytesUnit",
		"syncLLMReachability",
		"syncEnhanceMode",
		"@media (max-width: 767px)",
		"@media (prefers-reduced-motion: reduce)",
	} {
		if !strings.Contains(index, want) {
			t.Errorf("index.html missing preserved control/state %q", want)
		}
	}
	if got := strings.Count(index, "type=\"submit\" class=\"btn-primary\""); got != 1 {
		t.Errorf("primary scan submit buttons = %d, want 1", got)
	}

	scan := readUITemplate(t, "scan.html")
	for _, stage := range pipelineStepSpecs {
		if stage.ID == "dynamic-test" {
			continue
		}
		if !strings.Contains(scan, "id=\"step-"+stage.ID+"\"") {
			t.Errorf("scan.html missing stage %q", stage.ID)
		}
	}
	for _, want := range []string{
		"new EventSource('/scan/' + jobID + '/logs')",
		"'/scan/' + jobID + '/pipeline'",
		"'/scan/' + jobID + '/artifacts'",
		"class=\"section-panel runtime-log-panel\"",
		"id=\"selected-stage-results\"",
		"const stageResultDefinitions = {",
		"function element(tag, className, text)",
		"function renderStageResultHighlights()",
		"stages.c_parser.summary.call_graph_edges",
		"summary.confirmed_vulnerabilities",
		"stageResultMetricDisplay",
		"'/explore/' + encodeURIComponent(name)",
		"height: 460px",
		"@media (max-width: 767px)",
		"@media (prefers-reduced-motion: reduce)",
	} {
		if !strings.Contains(scan, want) {
			t.Errorf("scan.html missing preserved behavior/state %q", want)
		}
	}
}

func TestHomeProvidesPhaseNavigation(t *testing.T) {
	index := readUITemplate(t, "index.html")
	for _, want := range []string{
		"class=\"stage-nav\"",
		"id=\"stage-nav-toggle\"",
		"aria-controls=\"stage-nav-groups\"",
		"class=\"stage-nav-groups\"",
		"data-stage=\"exposure\"",
		"data-stage=\"source\"",
		"data-stage=\"static\"",
		"data-stage=\"analysis\"",
		"href=\"/device-socket-assets\"",
		"href=\"/exposure-locator\"",
		"href=\"/source-locator\"",
		"href=\"#new-scan-title\"",
		"href=\"#recent-title\"",
		"initStageNav",
		"persistStageNavState",
		"localStorage.getItem(stageNavStorageKey)",
		"nav.exposure.title",
		"nav.source.title",
		"nav.static.title",
		"nav.analysis.title",
		"nav.analysis.assets",
		"/device-socket-assets/history",
		"/dynamic-test",
		"/dynamic-test-history",
	} {
		if !strings.Contains(index, want) {
			t.Errorf("index.html missing phase navigation marker %q", want)
		}
	}
	if got := strings.Count(index, "<details class=\"stage-nav-group\""); got != 4 {
		t.Errorf("phase navigation groups = %d, want 4", got)
	}
}

func TestDynamicHistoryProvidesProtectedDeleteAction(t *testing.T) {
	history := readUITemplate(t, "dynamic-test-history.html")
	for _, want := range []string{
		`meta name="csrf"`,
		`method:'DELETE'`,
		`/scan-artifact/runs/`,
		`CONFIRMED 会话受保护`,
		`删除会话`,
	} {
		if !strings.Contains(history, want) {
			t.Errorf("dynamic-test-history.html missing delete-safety marker %q", want)
		}
	}
}

func TestHomeBrandUsesVulnFounderAndOmitsEntryRiskTagline(t *testing.T) {
	index := readUITemplate(t, "index.html")
	if !strings.Contains(index, "<h1>vulnfounder</h1>") {
		t.Fatal("index.html must display vulnfounder as the home brand")
	}
	if strings.Contains(index, "<h1>VulnFounder</h1>") {
		t.Fatal("index.html still displays the old VulnFounder home brand")
	}
	if strings.Contains(index, "从源码入口追踪安全风险") {
		t.Fatal("the removed entry-point risk tagline is still present")
	}
}

func TestWebVisibleSourceAvoidsLongDashCharacters(t *testing.T) {
	for _, name := range []string{"index.html", "scan.html"} {
		body := readUITemplate(t, name)
		if strings.ContainsAny(body, "—–") {
			t.Errorf("%s contains a forbidden long dash character", name)
		}
	}
}

func TestScanPageProvidesAccessibleStageMenusAndArtifactFiltering(t *testing.T) {
	scan := readUITemplate(t, "scan.html")
	for _, want := range []string{
		"role=\"tablist\"",
		"role=\"tab\"",
		"aria-selected=\"true\"",
		"aria-controls=\"stage-workbench\"",
		"role=\"tabpanel\"",
		"data-stage=\"parse\"",
		"artifact.stage === selectedStage",
		"artifact.description",
		"selected-stage-inputs",
		"selected-stage-outputs",
		"details.raw",
		"event.key === 'ArrowDown'",
		"event.key === 'Home'",
	} {
		if !strings.Contains(scan, want) {
			t.Errorf("scan.html missing stage-menu behavior %q", want)
		}
	}
}

func TestNewScanHidesUnsupportedScopeLevels(t *testing.T) {
	index := readUITemplate(t, "index.html")
	for _, option := range []string{
		`<option value="codeql"`,
		`<option value="exploitable"`,
	} {
		if strings.Contains(index, option) {
			t.Errorf("index.html still exposes unsupported execution-level option %q", option)
		}
	}
	if !strings.Contains(index, `<option value="reachable" selected`) || !strings.Contains(index, `<option value="all"`) {
		t.Fatal("index.html must keep reachable and all as the visible scan levels")
	}
}

func TestScanPageRendersReachabilityCollectionsAsCountsWithDetails(t *testing.T) {
	scan := readUITemplate(t, "scan.html")
	for _, marker := range []string{
		"stageResultMetricCollectionInfo",
		"semantic_seed_ids: ['个语义 BFS 种子'",
		"reachable_only_ids: ['个 medium 直接保留单元'",
		"details.metricItems",
		"detailItems.slice(0, 40)",
		"const showMetricDetails = metricKey !== 'semantic_seed_ids'",
		"align-items: start",
	} {
		if !strings.Contains(scan, marker) {
			t.Errorf("scan.html missing readable reachability metric marker %q", marker)
		}
	}
}

func TestScanPageEvidenceCardsDoNotStretchAcrossGridRows(t *testing.T) {
	scan := readUITemplate(t, "scan.html")
	for _, marker := range []string{
		".stage-result-evidence-list {",
		"align-items: start",
		".stage-result-evidence-card {",
		"align-self: start",
		"height: max-content",
		"cards now open exactly on the click that selects them",
	} {
		if !strings.Contains(scan, marker) {
			t.Errorf("scan.html missing independent evidence-card layout marker %q", marker)
		}
	}
}

func TestSummaryAndDisclosureTemplatesUseReadableReportPresentation(t *testing.T) {
	summary := readUITemplate(t, "summary.html")
	for _, marker := range []string{
		"removeChineseStageCostSection",
		"[费用成本]",
		"[阶段流水线管线]",
	} {
		if !strings.Contains(summary, marker) {
			t.Errorf("summary.html missing cost-section presentation marker %q", marker)
		}
	}
	disclosure := readUITemplate(t, "disclosure.html")
	for _, marker := range []string{
		"color: #ffffff !important",
		"background: transparent !important",
		".content pre code",
	} {
		if !strings.Contains(disclosure, marker) {
			t.Errorf("disclosure.html missing readable code-block marker %q", marker)
		}
	}
}

func TestScanPageProvidesStructuredArtifactExplorer(t *testing.T) {
	scan := readUITemplate(t, "scan.html")
	for _, want := range []string{
		"/explore/",
		"explorer-structured-button",
		"explorer-raw-button",
		"explorer-search",
		"explorer-items",
		"explorer-item-detail",
		"explorer-previous",
		"explorer-next",
		"available_collections",
		"openExplorer(artifact.name)",
		"loadExplorerItem",
		"details.dataset.loaded",
	} {
		if !strings.Contains(scan, want) {
			t.Errorf("scan.html missing structured explorer behavior %q", want)
		}
	}
}

func TestScanPageUsesCanonicalCallGraphStageCounters(t *testing.T) {
	scan := readUITemplate(t, "scan.html")
	for _, want := range []string{
		"summary.sites_scheduled",
		"summary.sites_reviewed",
		"summary.accepted_decisions",
		"summary.kept_unresolved",
		"summary.parsed_decisions",
		"summary.worklist_sites",
		"stageResultMetricDisplay(groups, [",
		"stageResultRecoveryUnresolvedDisplay(groups)",
		"normalizeCallGraphStageArtifact(name, data)",
		"groups.splice(summaryIndex, 1)",
		"stage-result-evidence",
		"stageResultEvidenceRecords",
	} {
		if !strings.Contains(scan, want) {
			t.Errorf("scan.html missing canonical call-graph counter %q", want)
		}
	}
}

func TestScanPageProvidesCallGraphEvidenceCards(t *testing.T) {
	scan := readUITemplate(t, "scan.html")
	for _, want := range []string{
		"stage-result-evidence",
		"stageResultEvidence",
		"stageResultEvidenceRecords",
		"调用点",
		"证据片段",
		"未解决原因",
		"dispatch_code_values",
	} {
		if !strings.Contains(scan, want) {
			t.Errorf("scan.html missing call-graph evidence card marker %q", want)
		}
	}
}

func TestScanPageProvidesDisclosureFindingCards(t *testing.T) {
	scan := readUITemplate(t, "scan.html")
	for _, want := range []string{
		"disclosure-card",
		"disclosure.vulnerability_type",
		"disclosure.cwe_id",
		"disclosure.file_path",
		"disclosure.function",
		"disclosure.start_line",
		"disclosure.affected_version",
		"disclosure.repair_status",
		"disclosure.source_to_sink",
		"disclosure.call_chain",
		"disclosure.summary",
		"renderDisclosures(list)",
		"disclosure-evidence",
		"disclosure-call-chain",
		"disclosures.type",
		"disclosures.cwe",
		"disclosures.file",
		"disclosures.function",
		"disclosures.lines",
		"disclosures.affected",
		"disclosures.repair",
		"disclosures.evidence",
		"disclosures.sourceToSink",
		"disclosures.callChain",
		"disclosures.summary",
		"document.createTextNode(disclosure.summary",
		"disclosure-search",
		"disclosure-search-clear",
		"disclosureSearchText(disclosure)",
		"disclosures.searchPlaceholder",
		"disclosures.noMatches",
	} {
		if !strings.Contains(scan, want) {
			t.Errorf("scan.html missing disclosure card marker %q", want)
		}
	}
}

func TestScanPageLocalizesOpenHarmonySecurityContextSummaries(t *testing.T) {
	scan := readUITemplate(t, "scan.html")
	for _, want := range []string{
		"metadata.openharmony_scope.platform",
		"metadata.openharmony_scope.coverage.discovered_files",
		"metadata.openharmony_scope.build_metadata.bundle_manifests",
		"function stageResultValueSummary(value, path, depth)",
		"const stageResultCollectionLabels = {",
		"function stageResultCollectionSummary(value, path)",
		"function stageResultCompactText(text, path)",
		"function renderStageResultProfileDetails(parent, profiles, path)",
		"stage-result-detail-body",
		"stage-result-field-expanded",
		"grid-template-columns: 140px minmax(0, 1fr)",
		"本地普通 IPC 调用者",
		"function stageResultLocalizedString(value, path)",
		"Binder IPC 数据",
		"IPC 调用者身份",
		"不可信（外部可控）",
		"使用接口数据前，必须校验接口令牌、返回值、字段类型、字段宽度和字段顺序。",
		"在分配内存或开始遍历前，必须限制并校验来自 Parcel 的长度、数量、索引和回调注册信息。",
		"执行敏感 IPC 操作前，必须先完成调用者身份和权限检查，并确保检查覆盖整个敏感操作路径。",
	} {
		if !strings.Contains(scan, want) {
			t.Errorf("scan.html missing OpenHarmony-friendly rendering marker %q", want)
		}
	}
	if strings.Contains(scan, "[object Object]") {
		t.Fatal("scan.html still contains object-to-string coercion output")
	}
}

func TestScanPageProvidesClaudeCodeInteractiveWorkbench(t *testing.T) {
	index := readUITemplate(t, "index.html")
	for _, forbidden := range []string{
		"name=\"dynamic_test\"",
		"name=\"dynamic_test_mode\"",
		"syncDynamicTestMode",
	} {
		if strings.Contains(index, forbidden) {
			t.Errorf("index.html still exposes static-scan dynamic-test control %q", forbidden)
		}
	}
	scan := readUITemplate(t, "scan.html")
	for _, forbidden := range []string{
		"id=\"step-dynamic-test\"",
		"id=\"claude-workbench\"",
		"data-stage-panel=\"dynamic-test\"",
	} {
		if strings.Contains(scan, forbidden) {
			t.Errorf("scan.html still exposes static-scan dynamic-test content %q", forbidden)
		}
	}
	dynamic := readUITemplate(t, "dynamic-test.html")
	for _, want := range []string{"动态测试", "执行动态测试"} {
		if !strings.Contains(dynamic, want) {
			t.Errorf("dynamic-test.html missing standalone dynamic-test marker %q", want)
		}
	}
}

func TestScanPageOpensStandaloneArtifactViewerWithInlineFallback(t *testing.T) {
	scan := readUITemplate(t, "scan.html")
	for _, want := range []string{
		"function artifactViewEndpoint(name)",
		"window.open(",
		"/artifact-view/",
		"openInlineExplorer(name)",
		"popup=yes,width=1180,height=820",
	} {
		if !strings.Contains(scan, want) {
			t.Errorf("scan.html missing standalone artifact viewer behavior %q", want)
		}
	}
}

func TestStandaloneArtifactViewerTemplateProvidesIndependentShell(t *testing.T) {
	viewer := readUITemplate(t, "artifact-view.html")
	for _, want := range []string{
		"data-job-id=",
		"data-artifact-name=",
		"id=\"structured-view\"",
		"id=\"raw-view\"",
		"window.close()",
		"applyLanguage('zh-CN')",
		"function fieldInfo(key)",
		"function renderCollectionView(view)",
		"中文字段表单",
	} {
		if !strings.Contains(viewer, want) {
			t.Errorf("artifact-view.html missing standalone behavior %q", want)
		}
	}
}

func TestStandaloneArtifactViewerHasArtifactSpecificFieldRenderers(t *testing.T) {
	viewer := readUITemplate(t, "artifact-view.html")
	for _, want := range []string{
		"'dataset.json': ['解析单元数据集'",
		"'platform_profile.json': ['OpenHarmony 平台画像'",
		"'application_context.json': ['应用安全上下文'",
		"'results.json': ['第一阶段分析结果'",
		"'pipeline_output.json': ['统一管线输出'",
		"'parse.report.json': ['解析阶段执行记录'",
		"function appendObjectFields(parent, object, depth)",
		"function loadCollection(offset)",
		"collection-search",
		"field.unknown",
	} {
		if !strings.Contains(viewer, want) {
			t.Errorf("artifact-view.html missing artifact-specific renderer marker %q", want)
		}
	}
}

func TestStandaloneArtifactViewerExplainsExtendedFields(t *testing.T) {
	viewer := readUITemplate(t, "artifact-view.html")
	for _, want := range []string{
		"const additionalFields = {",
		"cost_amount: ['费用数值'",
		"input_tokens: ['输入 Token 数'",
		"reachability_filter_applied: ['是否应用可达性过滤'",
		"function generatedFieldInfo(key)",
		"原始字段名和值已完整保留",
	} {
		if !strings.Contains(viewer, want) {
			t.Errorf("artifact-view.html missing extended field explanation %q", want)
		}
	}
	if strings.Contains(viewer, "暂未登记专用解释") {
		t.Fatal("artifact-view.html still exposes the old unregistered-field placeholder")
	}
}

func TestStandaloneArtifactViewerPrioritizesFields(t *testing.T) {
	viewer := readUITemplate(t, "artifact-view.html")
	for _, want := range []string{
		"const focusFieldPaths = {",
		"element('section', 'focus-summary')",
		"function createFocusSummary(value, itemMode)",
		"function createFullFields(value)",
		"focus.expand",
		"focus.collapse",
		"arrayItemLabel(value, index)",
		"details.open = false",
	} {
		if !strings.Contains(viewer, want) {
			t.Errorf("artifact-view.html missing progressive viewing marker %q", want)
		}
	}
}

func TestStandaloneArtifactViewerLocalizesSecurityValues(t *testing.T) {
	viewer := readUITemplate(t, "artifact-view.html")
	for _, want := range []string{
		"openharmony_binder_parcel: ['Binder IPC 数据'",
		"openharmony_calling_identity: ['IPC 调用者身份'",
		"const securityValueTranslations = {",
		"使用接口数据前，必须校验接口令牌、返回值、字段类型、字段宽度和字段顺序。",
		"在分配内存或开始遍历前，必须限制并校验来自 Parcel 的长度、数量、索引和回调注册信息。",
		"执行敏感 IPC 操作前，必须先完成调用者身份和权限检查，并确保检查覆盖整个敏感操作路径。",
	} {
		if !strings.Contains(viewer, want) {
			t.Errorf("artifact-view.html missing localized security value marker %q", want)
		}
	}
}

func TestStandaloneArtifactViewerProvidesCallGraphCanvas(t *testing.T) {
	viewer := readUITemplate(t, "artifact-view.html")
	for _, want := range []string{
		"id=\"graph-button\"",
		"id=\"graph-entry-list\"",
		"id=\"graph-canvas\"",
		"id=\"graph-world\"",
		"id=\"graph-expand\"",
		"id=\"graph-collapse\"",
		"id=\"graph-depth-select\"",
		"GRAPH_DEFAULT_DEPTH = 3",
		"function graphVisibleSubgraph()",
		"function graphEntryRecords(dataset)",
		"function graphRenderSvg()",
		"const graphArtifacts = { 'call_graph.json': true, 'analyzer_output.json': true, 'dataset_enhanced.json': true }",
		"function graphBuildAgentic(graphJSON, datasetJSON)",
		"graph.agenticCanvasTitle",
		"agentic-context",
		"dataset.json entry marker",
		"graphCanvas.addEventListener('wheel'",
	} {
		if !strings.Contains(viewer, want) {
			t.Errorf("artifact-view.html missing call graph visualization marker %q", want)
		}
	}
}

func TestReportLanguageLinksArePresent(t *testing.T) {
	index := readUITemplate(t, "index.html")
	scan := readUITemplate(t, "scan.html")
	for name, body := range map[string]string{"index.html": index, "scan.html": scan} {
		for _, want := range []string{
			"lang=zh-CN",
			"action.summaryZh",
			"action.reportZh",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s missing localized report link %q", name, want)
			}
		}
	}
}

func TestScanPageProvidesStageOutcomeSummary(t *testing.T) {
	scan := readUITemplate(t, "scan.html")
	for _, want := range []string{
		"id=\"stage-results-lead\"",
		"function renderStageResultLead(step, groups)",
		"details.outcomeParse",
		"details.outcomeAnalyze",
		"details.outcomeVerify",
		"stage-result-lead.success",
		"stage-result-field.danger",
	} {
		if !strings.Contains(scan, want) {
			t.Errorf("scan.html missing stage outcome marker %q", want)
		}
	}
}
