package server

import (
	"html/template"
	"strings"
	"testing"

	uifiles "github.com/knostic/open-ant-cli/ui"
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
	for _, name := range []string{"index.html", "scan.html", "artifact-view.html", "source-locator.html"} {
		if _, err := template.ParseFS(uifiles.FS, name); err != nil {
			t.Errorf("parse %s: %v", name, err)
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
		"id=\"llm-config\"",
		"id=\"llm-rounds\"",
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
		"fetchSearchArtifact",
		"action.help",
		"minmax(260px,280px)",
		"aria-busy",
		"notice.running",
		"llm.search.round",
		"最多 20 轮",
		"up to 20 rounds",
		"隐藏思维链",
		"textContent",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("source-locator.html missing interactive marker %q", want)
		}
	}
}

func TestWebTemplatesProvidePersistentChineseEnglishSwitch(t *testing.T) {
	for _, name := range []string{"index.html", "scan.html", "artifact-view.html", "source-locator.html"} {
		body := readUITemplate(t, name)
		for _, want := range []string{
			"id=\"language-select\"",
			"value=\"zh-CN\"",
			"value=\"en\"",
			"openant.ui.language",
			"document.documentElement.lang",
			"data-i18n=",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s missing %q", name, want)
			}
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
		"name=\"verify\"",
		"name=\"dynamic_test\"",
		"name=\"library_mode\"",
		"name=\"llm_reachability\"",
		"name=\"llm_reachability_max_code_bytes\"",
		"reachability-value",
		"scan.llmReachabilityBytesUnit",
		"syncLLMReachability",
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

func TestHomeBrandUsesVulnFounderAndOmitsEntryRiskTagline(t *testing.T) {
	index := readUITemplate(t, "index.html")
	if !strings.Contains(index, "<h1>vulnfounder</h1>") {
		t.Fatal("index.html must display vulnfounder as the home brand")
	}
	if strings.Contains(index, "<h1>OpenAnt</h1>") {
		t.Fatal("index.html still displays the old OpenAnt home brand")
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

func TestScanPageProvidesDisclosureFindingCards(t *testing.T) {
	scan := readUITemplate(t, "scan.html")
	for _, want := range []string{
		"disclosure-card",
		"disclosure.vulnerability_type",
		"disclosure.file_path",
		"disclosure.function",
		"disclosure.summary",
		"disclosures.type",
		"disclosures.file",
		"disclosures.function",
		"disclosures.summary",
		"document.createTextNode(disclosure.summary",
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
	for _, want := range []string{
		"name=\"dynamic_test_mode\"",
		"value=\"claude-code\"",
		"syncDynamicTestMode",
	} {
		if !strings.Contains(index, want) {
			t.Errorf("index.html missing Claude Code mode control %q", want)
		}
	}
	scan := readUITemplate(t, "scan.html")
	for _, want := range []string{
		"id=\"claude-workbench\"",
		"/claude/events",
		"/claude/message",
		"/claude/files",
		"/claude/file?path=",
		"id=\"claude-transcript\"",
		"id=\"claude-file-tree\"",
	} {
		if !strings.Contains(scan, want) {
			t.Errorf("scan.html missing Claude Code workbench behavior %q", want)
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
		"localStorage.setItem('openant.ui.language'",
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
