package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

func testConfig(t *testing.T, directory string) *Config {
	t.Helper()
	return &Config{
		BaseURL:                 "http://grok2api:8000",
		InternalToken:           "scoped-secret",
		Model:                   "grok-4.5",
		NodeIDs:                 []string{"1"},
		Mode:                    "hybrid",
		ActiveIntervalSeconds:   1800,
		PassivePollSeconds:      5,
		SoftTPS:                 500,
		HardTPS:                 1000,
		ConsecutiveSoft:         2,
		ConsecutiveErrors:       2,
		QuarantineSeconds:       300,
		NoAccountBackoffSeconds: 300,
		MinHealthyNodes:         1,
		MaxOutputTokens:         384,
		MinGenerationMS:         1000,
		RotationTimeoutSeconds:  45,
		Prompt:                  "probe",
		Expected:                "QUALITY_OK",
		StateFile:               filepath.Join(directory, "state.json"),
		LockFile:                filepath.Join(directory, "guard.lock"),
		RuntimeConfigFile:       filepath.Join(directory, "runtime-config.json"),
	}
}

func TestClassifyResult(t *testing.T) {
	config := testConfig(t, t.TempDir())
	cases := []struct {
		name           string
		result         qualityResult
		classification string
		reason         string
	}{
		{"healthy", qualityResult{ExpectedMatched: true, OutputTokens: 100, OutputTokensPerSecond: float64Ptr(499)}, "healthy", "within_threshold"},
		{"soft", qualityResult{ExpectedMatched: true, OutputTokens: 100, OutputTokensPerSecond: float64Ptr(500)}, "soft", "soft_tps"},
		{"hard", qualityResult{ExpectedMatched: true, OutputTokens: 100, OutputTokensPerSecond: float64Ptr(1000)}, "hard", "hard_tps"},
		{"missing marker", qualityResult{OutputTokens: 100, OutputTokensPerSecond: float64Ptr(10)}, "soft", "expected_marker_missing"},
		{"short output", qualityResult{ExpectedMatched: true, OutputTokens: 12, OutputTokensPerSecond: float64Ptr(10)}, "soft", "insufficient_output_tokens"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			classification, reason := classifyResult(item.result, config)
			if classification != item.classification || reason != item.reason {
				t.Fatalf("got %s/%s, want %s/%s", classification, reason, item.classification, item.reason)
			}
		})
	}
}

func TestClassifyAuditIncludesReasoningTokens(t *testing.T) {
	config := testConfig(t, t.TempDir())
	firstToken := 1000
	classification, reason, speed, output := classifyAudit(auditValue{
		Provider: "grok_build", Streaming: true, StatusCode: 200,
		FirstTokenMS: &firstToken, DurationMS: 1100, OutputTokens: 1050,
	}, config)
	if classification != "hard" || reason != "hard_tps" || output != 1050 || speed != 10500 {
		t.Fatalf("got %s/%s %.0f %d", classification, reason, speed, output)
	}
}

func TestStateWriteIsAtomicPrivateAndMigratesLegacyTokens(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	state := State{
		Version: 1,
		Nodes:   map[string]*NodeState{"8": defaultNodeState()},
		Statistics: statistics{
			Active: detectionStats{LegacyTokens: 7},
		},
	}
	if err := saveState(path, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Statistics.Active.OutputTokens != 7 {
		t.Fatalf("legacy visible token count was not migrated: %+v", loaded.Statistics.Active)
	}
	if mode := os.FileMode(mustStat(t, path).Mode()).Perm(); mode != 0o600 {
		t.Fatalf("state mode = %o, want 600", mode)
	}
}

func TestRuntimeConfigReloaderKeepsLastValidConfig(t *testing.T) {
	directory := t.TempDir()
	config := testConfig(t, directory)
	reloader := newRuntimeReloader(config)
	loaded, changed, err := reloader.reload(true)
	if err != nil || !changed || loaded != config {
		t.Fatalf("initial reload = %v, %v, want base config", loaded, err)
	}
	runtime := map[string]any{
		"version": 1,
		"settings": map[string]any{
			"mode": "passive", "active_interval_seconds": 3600, "passive_poll_seconds": 10,
			"soft_tps": 400, "hard_tps": 900, "consecutive_soft": 3, "consecutive_errors": 4,
			"quarantine_seconds": 600, "min_healthy_nodes": 1,
		},
	}
	data, _ := json.Marshal(runtime)
	if err := os.WriteFile(config.RuntimeConfigFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, changed, err = reloader.reload(false)
	if err != nil || !changed || loaded.Mode != "passive" || loaded.SoftTPS != 400 {
		t.Fatalf("valid reload = %+v, changed=%v, err=%v", loaded, changed, err)
	}
	if err := os.WriteFile(config.RuntimeConfigFile, []byte(`{"version":1,"settings":{"mode":"invalid"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, changed, err = reloader.reload(false)
	if err == nil || !changed || loaded.Mode != "passive" {
		t.Fatalf("invalid reload = %+v, changed=%v, err=%v", loaded, changed, err)
	}
}

func TestAPIClientListNodesReadsEveryPage(t *testing.T) {
	requestedPages := make([]int, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		page, _ := strconv.Atoi(request.URL.Query().Get("page"))
		requestedPages = append(requestedPages, page)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		if page == 1 {
			items := make([]Node, 2000)
			for index := range items {
				items[index] = Node{ID: strconv.Itoa(index + 1)}
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": map[string]any{"items": items, "total": 2001}})
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"data": map[string]any{"items": []Node{{ID: "2001"}}, "total": 2001}})
	}))
	defer server.Close()
	config := testConfig(t, t.TempDir())
	config.BaseURL = server.URL
	nodes, err := newAPIClient(config).ListNodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2001 || !reflect.DeepEqual(requestedPages, []int{1, 2}) {
		t.Fatalf("got %d nodes and pages %v", len(nodes), requestedPages)
	}
}

func TestAPIClientRejectsIncompletePagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(map[string]any{"data": map[string]any{"items": []Node{}, "total": 1}})
	}))
	defer server.Close()
	config := testConfig(t, t.TempDir())
	config.BaseURL = server.URL
	if _, err := newAPIClient(config).ListNodes(); err == nil {
		t.Fatal("incomplete pagination was accepted")
	}
}

type fakeResult struct {
	value qualityResult
	err   error
}

type fakeAPI struct {
	nodes         []*Node
	results       []fakeResult
	auditPages    []auditPage
	enabledCalls  [][2]any
	qualityCalls  []string
	rotationCalls []string
}

func (f *fakeAPI) ListNodes() ([]*Node, error) { return f.nodes, nil }
func (f *fakeAPI) FixedFallbackNodeIDs() (map[string]struct{}, error) {
	return map[string]struct{}{}, nil
}
func (f *fakeAPI) QualityTest(nodeID string) (qualityResult, error) {
	f.qualityCalls = append(f.qualityCalls, nodeID)
	if len(f.results) == 0 {
		return qualityResult{}, errors.New("no fake result")
	}
	result := f.results[0]
	f.results = f.results[1:]
	return result.value, result.err
}
func (f *fakeAPI) ConnectivityTest(string) (map[string]any, error) {
	return map[string]any{"status": "healthy"}, nil
}
func (f *fakeAPI) ListAudits(string) (auditPage, error) {
	if len(f.auditPages) == 0 {
		return auditPage{}, nil
	}
	page := f.auditPages[0]
	f.auditPages = f.auditPages[1:]
	return page, nil
}
func (f *fakeAPI) SetEnabled(nodeID string, enabled bool) (int, error) {
	f.enabledCalls = append(f.enabledCalls, [2]any{nodeID, enabled})
	for _, node := range f.nodes {
		if node.ID == nodeID {
			node.Enabled = enabled
			return 1, nil
		}
	}
	return 0, nil
}
func (f *fakeAPI) RotateNode(nodeID, _ string) (rotationResponse, error) {
	f.rotationCalls = append(f.rotationCalls, nodeID)
	return rotationResponse{Changed: true, NewExitIP: "203.0.113.10"}, nil
}

func TestGuardQuarantinesAndRestoresHealthyNode(t *testing.T) {
	directory := t.TempDir()
	config := testConfig(t, directory)
	config.Mode = "active"
	nodes := []*Node{
		{ID: "1", Name: "node-1", Enabled: true, ProxyConfigured: true},
		{ID: "2", Name: "node-2", Enabled: true, ProxyConfigured: true},
	}
	api := &fakeAPI{nodes: nodes, results: []fakeResult{
		{value: qualityResult{ExpectedMatched: true, OutputTokens: 100, OutputTokensPerSecond: float64Ptr(1200)}},
		{value: qualityResult{ExpectedMatched: true, OutputTokens: 100, OutputTokensPerSecond: float64Ptr(100)}},
	}}
	guard, err := newGuard(config, api)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.runActiveCycle(); err != nil {
		t.Fatal(err)
	}
	if !guard.state.Nodes["1"].DisabledByGuard || !reflect.DeepEqual(api.enabledCalls, [][2]any{{"1", false}}) {
		t.Fatalf("node was not quarantined: %+v calls=%v", guard.state.Nodes["1"], api.enabledCalls)
	}
	guard.state.Nodes["1"].QuarantinedUntil = 0
	if err := guard.runActiveCycle(); err != nil {
		t.Fatal(err)
	}
	if guard.state.Nodes["1"].DisabledByGuard || !nodes[0].Enabled {
		t.Fatalf("node was not restored: %+v", guard.state.Nodes["1"])
	}
	if !reflect.DeepEqual(api.enabledCalls, [][2]any{{"1", false}, {"1", true}}) {
		t.Fatalf("enable calls = %v", api.enabledCalls)
	}
}

func TestGuardSuppressesQuarantineBelowHealthyFloor(t *testing.T) {
	directory := t.TempDir()
	config := testConfig(t, directory)
	config.MinHealthyNodes = 2
	nodes := []*Node{
		{ID: "1", Name: "node-1", Enabled: true, ProxyConfigured: true},
		{ID: "2", Name: "node-2", Enabled: true, ProxyConfigured: true},
	}
	api := &fakeAPI{nodes: nodes, results: []fakeResult{{value: qualityResult{ExpectedMatched: true, OutputTokens: 100, OutputTokensPerSecond: float64Ptr(1200)}}}}
	guard, err := newGuard(config, api)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.runActiveCycle(); err != nil {
		t.Fatal(err)
	}
	if len(api.enabledCalls) != 0 || guard.state.Nodes["1"].DisabledByGuard {
		t.Fatalf("quarantine was not suppressed: calls=%v state=%+v", api.enabledCalls, guard.state.Nodes["1"])
	}
}

func float64Ptr(value float64) *float64 { return &value }

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	value, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
