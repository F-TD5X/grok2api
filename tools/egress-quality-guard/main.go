package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	bootstrapVersion = 1
	bootstrapPath    = "/var/lib/grok2api-quality-guard/bootstrap.json"
	statePath        = "/var/lib/grok2api-quality-guard/state.json"
	lockPath         = "/var/lib/grok2api-quality-guard/guard.lock"
	runtimePath      = "/var/lib/grok2api-quality-guard/runtime-config.json"
	internalPrefix   = "/api/internal/v1/quality-guard"
	pageSize         = 2000
	passivePageSize  = 200
	passiveMaxPages  = 10
	jitterSeconds    = 30
	requestTimeout   = 120
	maxResponseBytes = 16 << 20
)

var errGuardDisabled = errors.New("qualityGuard.enabled is false in config.yaml")

// Config contains the immutable bootstrap values and the hot-reloadable
// policy. Paths and transport defaults intentionally match the Python guard.
type Config struct {
	BaseURL                 string
	InternalToken           string
	Model                   string
	NodeIDs                 []string
	Mode                    string
	ActiveIntervalSeconds   int
	PassivePollSeconds      int
	SoftTPS                 float64
	HardTPS                 float64
	ConsecutiveSoft         int
	ConsecutiveErrors       int
	QuarantineSeconds       int
	NoAccountBackoffSeconds int
	MinHealthyNodes         int
	MaxOutputTokens         int
	FailClosed              bool
	MinGenerationMS         int
	RotationURL             string
	RotationToken           string
	RotationTimeoutSeconds  int
	RotatableNodeIDs        []string
	Prompt                  string
	Expected                string
	StateFile               string
	LockFile                string
	RuntimeConfigFile       string
}

type bootstrapFile struct {
	Version       int             `json:"version"`
	Enabled       bool            `json:"enabled"`
	InternalToken string          `json:"internal_token"`
	Config        bootstrapConfig `json:"config"`
}

type bootstrapConfig struct {
	Model                   string   `json:"model"`
	Prompt                  string   `json:"prompt"`
	Expected                string   `json:"expected"`
	NodeIDs                 []string `json:"node_ids"`
	Mode                    string   `json:"mode"`
	ActiveIntervalSeconds   int      `json:"active_interval_seconds"`
	PassivePollSeconds      int      `json:"passive_poll_seconds"`
	SoftTPS                 float64  `json:"soft_tps"`
	HardTPS                 float64  `json:"hard_tps"`
	ConsecutiveSoft         int      `json:"consecutive_soft"`
	ConsecutiveErrors       int      `json:"consecutive_errors"`
	QuarantineSeconds       int      `json:"quarantine_seconds"`
	NoAccountBackoffSeconds int      `json:"no_account_backoff_seconds"`
	MinHealthyNodes         int      `json:"min_healthy_nodes"`
	MaxOutputTokens         int      `json:"max_output_tokens"`
	FailClosed              bool     `json:"fail_closed"`
	MinGenerationMS         int      `json:"min_generation_ms"`
	RotationURL             string   `json:"rotation_url"`
	RotationToken           string   `json:"rotation_token"`
	RotationTimeoutSeconds  int      `json:"rotation_timeout_seconds"`
	RotatableNodeIDs        []string `json:"rotatable_node_ids"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("quality guard bootstrap file is missing; restart grok2api")
		}
		return nil, fmt.Errorf("cannot read quality guard bootstrap: %T", err)
	}
	var value bootstrapFile
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("cannot read quality guard bootstrap: %T", err)
	}
	if value.Version != bootstrapVersion {
		return nil, errors.New("unsupported quality guard bootstrap")
	}
	if !value.Enabled {
		return nil, errGuardDisabled
	}
	c := value.Config
	config := &Config{
		BaseURL:                 "http://grok2api:8000",
		InternalToken:           strings.TrimSpace(value.InternalToken),
		Model:                   strings.TrimSpace(c.Model),
		NodeIDs:                 uniqueStrings(c.NodeIDs),
		Mode:                    strings.ToLower(strings.TrimSpace(c.Mode)),
		ActiveIntervalSeconds:   c.ActiveIntervalSeconds,
		PassivePollSeconds:      c.PassivePollSeconds,
		SoftTPS:                 c.SoftTPS,
		HardTPS:                 c.HardTPS,
		ConsecutiveSoft:         c.ConsecutiveSoft,
		ConsecutiveErrors:       c.ConsecutiveErrors,
		QuarantineSeconds:       c.QuarantineSeconds,
		NoAccountBackoffSeconds: c.NoAccountBackoffSeconds,
		MinHealthyNodes:         c.MinHealthyNodes,
		MaxOutputTokens:         c.MaxOutputTokens,
		FailClosed:              c.FailClosed,
		MinGenerationMS:         c.MinGenerationMS,
		RotationURL:             strings.TrimSpace(c.RotationURL),
		RotationToken:           c.RotationToken,
		RotationTimeoutSeconds:  c.RotationTimeoutSeconds,
		RotatableNodeIDs:        uniqueStrings(c.RotatableNodeIDs),
		Prompt:                  strings.TrimSpace(c.Prompt),
		Expected:                strings.TrimSpace(c.Expected),
		StateFile:               statePath,
		LockFile:                lockPath,
		RuntimeConfigFile:       runtimePath,
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return config, nil
}

func (c *Config) validate() error {
	parsed, err := url.Parse(c.BaseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return errors.New("GROK2API_BASE_URL must be an absolute HTTP(S) URL")
	}
	if c.InternalToken == "" {
		return errors.New("quality guard bootstrap internal token is missing")
	}
	if c.Model == "" || c.Prompt == "" || c.Expected == "" {
		return errors.New("model, prompt, and expected marker must not be empty")
	}
	if c.Mode != "active" && c.Mode != "passive" && c.Mode != "hybrid" {
		return errors.New("qualityGuard.mode must be active, passive, or hybrid")
	}
	if c.ActiveIntervalSeconds < 60 || c.ActiveIntervalSeconds > 86400 {
		return errors.New("qualityGuard.activeInterval must be between 60 seconds and 24 hours")
	}
	if c.PassivePollSeconds < 1 || c.PassivePollSeconds > 300 {
		return errors.New("qualityGuard.passivePollInterval must be between 1 second and 5 minutes")
	}
	if c.SoftTPS < 1 || c.SoftTPS >= c.HardTPS {
		return errors.New("qualityGuard.softTPS must be lower than qualityGuard.hardTPS")
	}
	if c.SoftTPS > 10000 || c.HardTPS > 10000 {
		return errors.New("quality guard Token/s thresholds must not exceed 10000")
	}
	if c.ConsecutiveSoft < 1 || c.ConsecutiveSoft > 20 || c.ConsecutiveErrors < 1 || c.ConsecutiveErrors > 20 {
		return errors.New("quality guard consecutive strike limits must be between 1 and 20")
	}
	if c.QuarantineSeconds < 30 || c.QuarantineSeconds > 86400 || c.NoAccountBackoffSeconds < 30 || c.NoAccountBackoffSeconds > 86400 {
		return errors.New("quality guard quarantine and no-account backoff must be between 30 seconds and 24 hours")
	}
	if c.MaxOutputTokens < 32 || c.MaxOutputTokens > 4096 {
		return errors.New("qualityGuard.maxOutputTokens must be between 32 and 4096")
	}
	if c.MinGenerationMS < 1 || c.MinGenerationMS > 2*60*1000 {
		return errors.New("qualityGuard.minimumGenerationWindow must be between 1 millisecond and 2 minutes")
	}
	if c.RotationTimeoutSeconds < 5 || c.RotationTimeoutSeconds > 300 {
		return errors.New("qualityGuard.rotationTimeout must be between 5 seconds and 5 minutes")
	}
	if c.MinHealthyNodes < 1 || (len(c.NodeIDs) > 0 && c.MinHealthyNodes > len(c.NodeIDs)) {
		return errors.New("qualityGuard.minimumHealthyNodes must fit the configured node count")
	}
	if c.MinGenerationMS > requestTimeout*1000 {
		return errors.New("qualityGuard.minimumGenerationWindow must fit the request timeout")
	}
	if c.RotationURL != "" {
		rotationURL, err := url.Parse(c.RotationURL)
		if err != nil || (rotationURL.Scheme != "http" && rotationURL.Scheme != "https") || rotationURL.Host == "" || rotationURL.User != nil {
			return errors.New("qualityGuard.rotationURL must be an absolute HTTP(S) URL without credentials")
		}
	} else if len(c.RotatableNodeIDs) > 0 {
		return errors.New("qualityGuard.rotationURL is required when rotatableNodeIDs are configured")
	}
	for _, value := range c.RotatableNodeIDs {
		number, err := strconv.Atoi(value)
		if err != nil || number < 1 || strings.TrimSpace(value) == "" {
			return errors.New("qualityGuard.rotatableNodeIDs must contain positive integers")
		}
	}
	return nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

var runtimeFields = map[string]struct{}{
	"mode":                    {},
	"active_interval_seconds": {},
	"passive_poll_seconds":    {},
	"soft_tps":                {},
	"hard_tps":                {},
	"consecutive_soft":        {},
	"consecutive_errors":      {},
	"quarantine_seconds":      {},
	"min_healthy_nodes":       {},
}

type runtimeSettings struct {
	Mode                  string
	ActiveIntervalSeconds int
	PassivePollSeconds    int
	SoftTPS               float64
	HardTPS               float64
	ConsecutiveSoft       int
	ConsecutiveErrors     int
	QuarantineSeconds     int
	MinHealthyNodes       int
}

func loadRuntimeConfig(base *Config, path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read runtime quality guard config: %T", err)
	}
	var top struct {
		Version  int             `json:"version"`
		Settings json.RawMessage `json:"settings"`
	}
	if err := json.Unmarshal(data, &top); err != nil || top.Version != 1 || len(top.Settings) == 0 || bytes.Equal(bytes.TrimSpace(top.Settings), []byte("null")) {
		return nil, errors.New("unsupported runtime quality guard config")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(top.Settings, &raw); err != nil || raw == nil {
		return nil, errors.New("unsupported runtime quality guard config")
	}
	if len(raw) != len(runtimeFields) {
		return nil, errors.New("runtime quality guard config is incomplete")
	}
	for name := range raw {
		if _, ok := runtimeFields[name]; !ok {
			return nil, errors.New("runtime quality guard config contains unknown fields")
		}
	}
	var settings runtimeSettings
	if err := decodeRuntimeString(raw, "mode", &settings.Mode); err != nil {
		return nil, errors.New("runtime quality guard mode must be a string")
	}
	for _, field := range []struct {
		name   string
		target *int
	}{
		{"active_interval_seconds", &settings.ActiveIntervalSeconds},
		{"passive_poll_seconds", &settings.PassivePollSeconds},
		{"consecutive_soft", &settings.ConsecutiveSoft},
		{"consecutive_errors", &settings.ConsecutiveErrors},
		{"quarantine_seconds", &settings.QuarantineSeconds},
		{"min_healthy_nodes", &settings.MinHealthyNodes},
	} {
		if err := decodeRuntimeInt(raw, field.name, field.target); err != nil {
			return nil, errors.New("runtime quality guard integer field is invalid")
		}
	}
	if err := decodeRuntimeFloat(raw, "soft_tps", &settings.SoftTPS); err != nil {
		return nil, errors.New("runtime quality guard threshold is invalid")
	}
	if err := decodeRuntimeFloat(raw, "hard_tps", &settings.HardTPS); err != nil {
		return nil, errors.New("runtime quality guard threshold is invalid")
	}
	candidate := *base
	candidate.Mode = settings.Mode
	candidate.ActiveIntervalSeconds = settings.ActiveIntervalSeconds
	candidate.PassivePollSeconds = settings.PassivePollSeconds
	candidate.SoftTPS = settings.SoftTPS
	candidate.HardTPS = settings.HardTPS
	candidate.ConsecutiveSoft = settings.ConsecutiveSoft
	candidate.ConsecutiveErrors = settings.ConsecutiveErrors
	candidate.QuarantineSeconds = settings.QuarantineSeconds
	candidate.MinHealthyNodes = settings.MinHealthyNodes
	if err := candidate.validate(); err != nil {
		return nil, err
	}
	return &candidate, nil
}

func decodeRuntimeString(values map[string]json.RawMessage, name string, target *string) error {
	raw, ok := values[name]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("missing string")
	}
	return json.Unmarshal(raw, target)
}

func decodeRuntimeInt(values map[string]json.RawMessage, name string, target *int) error {
	raw, ok := values[name]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("missing integer")
	}
	return json.Unmarshal(raw, target)
}

func decodeRuntimeFloat(values map[string]json.RawMessage, name string, target *float64) error {
	raw, ok := values[name]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("missing number")
	}
	return json.Unmarshal(raw, target)
}

func sameRuntimeConfig(a, b *Config) bool {
	return a.Mode == b.Mode &&
		a.ActiveIntervalSeconds == b.ActiveIntervalSeconds &&
		a.PassivePollSeconds == b.PassivePollSeconds &&
		a.SoftTPS == b.SoftTPS &&
		a.HardTPS == b.HardTPS &&
		a.ConsecutiveSoft == b.ConsecutiveSoft &&
		a.ConsecutiveErrors == b.ConsecutiveErrors &&
		a.QuarantineSeconds == b.QuarantineSeconds &&
		a.MinHealthyNodes == b.MinHealthyNodes
}

type fileSignature struct {
	valid    bool
	missing  bool
	modified int64
	size     int64
}

type runtimeReloader struct {
	base        *Config
	current     *Config
	signature   fileSignature
	hasPrevious bool
}

func newRuntimeReloader(base *Config) *runtimeReloader {
	return &runtimeReloader{base: base, current: base}
}

func (r *runtimeReloader) reload(force bool) (*Config, bool, error) {
	info, err := os.Stat(r.base.RuntimeConfigFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return r.current, false, err
	}
	signature := fileSignature{}
	if errors.Is(err, os.ErrNotExist) {
		signature.missing = true
	} else {
		signature.valid = true
		signature.modified = info.ModTime().UnixNano()
		signature.size = info.Size()
	}
	if !force && r.hasPrevious && signature == r.signature {
		return r.current, false, nil
	}
	r.hasPrevious = true
	r.signature = signature
	candidate := r.base
	if !signature.missing {
		candidate, err = loadRuntimeConfig(r.base, r.base.RuntimeConfigFile)
		if err != nil {
			return r.current, true, err
		}
	}
	changed := force || !sameRuntimeConfig(candidate, r.current)
	r.current = candidate
	return candidate, changed, nil
}

// Node and API response types are intentionally limited to the fields the
// guard consumes. Unknown backend fields remain harmless during upgrades.
type Node struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Enabled         bool   `json:"enabled"`
	ProxyConfigured bool   `json:"proxyConfigured"`
	ExitIP          string `json:"exitIp"`
}

type nodePage struct {
	Items []*Node `json:"items"`
	Total int     `json:"total"`
}

type fallback struct {
	Mode   string `json:"mode"`
	NodeID string `json:"nodeId"`
}

type operationsResponse struct {
	Fallbacks map[string]fallback `json:"fallbacks"`
}

type qualityResult struct {
	ExpectedMatched        bool     `json:"expectedMatched"`
	OutputTokens           int      `json:"outputTokens"`
	VisibleTokens          int      `json:"visibleTokens"`
	OutputTokensPerSecond  *float64 `json:"outputTokensPerSecond"`
	VisibleTokensPerSecond *float64 `json:"visibleTokensPerSecond"`
	GenerationMS           int      `json:"generationMs"`
	DurationMS             int      `json:"durationMs"`
	FirstTokenMS           int      `json:"firstTokenMs"`
	ChunkCount             int      `json:"chunkCount"`
}

type auditValue struct {
	ID           string `json:"id"`
	RequestID    string `json:"requestId"`
	QualityProbe bool   `json:"qualityProbe"`
	Provider     string `json:"provider"`
	EgressNodeID string `json:"egressNodeId"`
	StatusCode   int    `json:"statusCode"`
	Streaming    bool   `json:"streaming"`
	OutputTokens int    `json:"outputTokens"`
	FirstTokenMS *int   `json:"firstTokenMs"`
	DurationMS   int    `json:"durationMs"`
	ErrorCode    string `json:"errorCode"`
}

type auditPage struct {
	Items      []auditValue `json:"items"`
	NextCursor string       `json:"nextCursor"`
	HasMore    bool         `json:"hasMore"`
}

type updateResponse struct {
	Updated int `json:"updated"`
}

type rotationResponse struct {
	Changed   bool   `json:"changed"`
	NodeID    string `json:"nodeId"`
	NewExitIP string `json:"newExitIp"`
}

type apiErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

type qualityAPI interface {
	ListNodes() ([]*Node, error)
	FixedFallbackNodeIDs() (map[string]struct{}, error)
	QualityTest(nodeID string) (qualityResult, error)
	ConnectivityTest(nodeID string) (map[string]any, error)
	ListAudits(cursor string) (auditPage, error)
	SetEnabled(nodeID string, enabled bool) (int, error)
	RotateNode(nodeID string, oldExitIP string) (rotationResponse, error)
}

type APIClient struct {
	config *Config
	client *http.Client
}

func newAPIClient(config *Config) *APIClient {
	return &APIClient{config: config, client: &http.Client{}}
}

func (c *APIClient) request(method, path string, body any, output any) error {
	return c.requestURL(c.config.BaseURL+path, method, body, output, requestTimeout, c.config.InternalToken)
}

func (c *APIClient) requestURL(rawURL, method string, body any, output any, timeoutSeconds int, token string) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return fmt.Errorf("request failed: %T", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %T", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("request failed: %T", err)
	}
	if len(data) > maxResponseBytes {
		return errors.New("request response is too large")
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err != nil {
		if resp.StatusCode >= 400 {
			return &APIError{Status: resp.StatusCode, Code: "request_failed", Message: "request failed"}
		}
		return fmt.Errorf("request response is invalid: %T", err)
	}
	if resp.StatusCode >= 400 {
		var payload apiErrorPayload
		if raw := envelope["error"]; len(raw) > 0 {
			_ = json.Unmarshal(raw, &payload)
		}
		if payload.Code == "" {
			payload.Code = "request_failed"
		}
		if payload.Message == "" {
			payload.Message = "request failed"
		}
		return &APIError{Status: resp.StatusCode, Code: payload.Code, Message: payload.Message}
	}
	payload := data
	if raw := envelope["data"]; len(raw) > 0 {
		payload = raw
	}
	if output != nil && len(payload) > 0 && !bytes.Equal(bytes.TrimSpace(payload), []byte("null")) {
		if err := json.Unmarshal(payload, output); err != nil {
			return fmt.Errorf("request response is invalid: %T", err)
		}
	}
	return nil
}

func (c *APIClient) ListNodes() ([]*Node, error) {
	items := make([]*Node, 0)
	seen := make(map[string]struct{})
	for page := 1; ; page++ {
		query := url.Values{}
		query.Set("page", strconv.Itoa(page))
		query.Set("pageSize", strconv.Itoa(pageSize))
		query.Set("scope", "grok_build")
		var value nodePage
		if err := c.request("GET", internalPrefix+"/egress-nodes?"+query.Encode(), nil, &value); err != nil {
			return nil, err
		}
		total := maxInt(value.Total, 0)
		added := 0
		for _, node := range value.Items {
			if node == nil || node.ID == "" {
				continue
			}
			if _, ok := seen[node.ID]; ok {
				continue
			}
			seen[node.ID] = struct{}{}
			items = append(items, node)
			added++
		}
		if len(items) >= total || (total == 0 && len(value.Items) < pageSize) {
			return items, nil
		}
		if len(value.Items) == 0 || added == 0 {
			return nil, fmt.Errorf("egress node pagination stopped at %d of %d", len(items), total)
		}
	}
}

func (c *APIClient) FixedFallbackNodeIDs() (map[string]struct{}, error) {
	var value operationsResponse
	if err := c.request("GET", internalPrefix+"/egress-operations", nil, &value); err != nil {
		return nil, err
	}
	result := make(map[string]struct{})
	for _, item := range value.Fallbacks {
		if item.Mode == "fixed" && item.NodeID != "" {
			result[item.NodeID] = struct{}{}
		}
	}
	return result, nil
}

func (c *APIClient) QualityTest(nodeID string) (qualityResult, error) {
	var value qualityResult
	err := c.request("POST", internalPrefix+"/egress-nodes/"+url.PathEscape(nodeID)+"/quality-test", nil, &value)
	return value, err
}

func (c *APIClient) ConnectivityTest(nodeID string) (map[string]any, error) {
	var value map[string]any
	err := c.request("POST", internalPrefix+"/egress-nodes/"+url.PathEscape(nodeID)+"/test", nil, &value)
	return value, err
}

func (c *APIClient) ListAudits(cursor string) (auditPage, error) {
	query := url.Values{}
	query.Set("pagination", "cursor")
	query.Set("pageSize", strconv.Itoa(passivePageSize))
	query.Set("period", "24h")
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	var value auditPage
	err := c.request("GET", internalPrefix+"/request-audits?"+query.Encode(), nil, &value)
	return value, err
}

func (c *APIClient) SetEnabled(nodeID string, enabled bool) (int, error) {
	body := struct {
		IDs     []string `json:"ids"`
		Enabled bool     `json:"enabled"`
	}{IDs: []string{nodeID}, Enabled: enabled}
	var value updateResponse
	if err := c.request("PATCH", internalPrefix+"/egress-nodes/batch", body, &value); err != nil {
		return 0, err
	}
	return value.Updated, nil
}

func (c *APIClient) RotateNode(nodeID string, oldExitIP string) (rotationResponse, error) {
	if c.config.RotationURL == "" {
		return rotationResponse{}, errors.New("rotation endpoint is not configured")
	}
	body := struct {
		NodeID    string `json:"nodeId"`
		OldExitIP string `json:"oldExitIp"`
	}{NodeID: nodeID, OldExitIP: oldExitIP}
	var value rotationResponse
	if err := c.requestURL(c.config.RotationURL, "POST", body, &value, c.config.RotationTimeoutSeconds, c.config.RotationToken); err != nil {
		return rotationResponse{}, fmt.Errorf("rotation failed: %w", err)
	}
	if !value.Changed {
		return rotationResponse{}, errors.New("rotation did not confirm an exit IP change")
	}
	return value, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func valueOrInt(value, fallback int) int {
	if value != 0 {
		return value
	}
	return fallback
}

func outputTokens(result qualityResult) int {
	if result.OutputTokens != 0 {
		return result.OutputTokens
	}
	return result.VisibleTokens
}

func outputTPS(result qualityResult) float64 {
	if result.OutputTokensPerSecond != nil {
		return *result.OutputTokensPerSecond
	}
	if result.VisibleTokensPerSecond != nil {
		return *result.VisibleTokensPerSecond
	}
	return 0
}

func classifyResult(result qualityResult, config *Config) (string, string) {
	if !result.ExpectedMatched {
		return "soft", "expected_marker_missing"
	}
	if outputTokens(result) < 32 {
		return "soft", "insufficient_output_tokens"
	}
	generationMS := result.GenerationMS
	if generationMS <= 0 {
		generationMS = maxInt(0, result.DurationMS-result.FirstTokenMS)
	}
	if config.FailClosed && generationMS < config.MinGenerationMS {
		return "soft", "insufficient_generation_window"
	}
	speed := outputTPS(result)
	if speed >= config.HardTPS {
		return "hard", "hard_tps"
	}
	if speed >= config.SoftTPS {
		return "soft", "soft_tps"
	}
	return "healthy", "within_threshold"
}

func classifyAudit(value auditValue, config *Config) (string, string, float64, int) {
	if value.Provider != "grok_build" || !value.Streaming {
		return "ignored", "not_build_stream", 0, 0
	}
	if value.StatusCode < 200 || value.StatusCode >= 300 || value.ErrorCode != "" {
		return "ignored", "unsuccessful", 0, 0
	}
	if value.FirstTokenMS == nil {
		return "ignored", "missing_first_token", 0, 0
	}
	generationMS := value.DurationMS - *value.FirstTokenMS
	outputTokens := maxInt(value.OutputTokens, 0)
	if generationMS <= 0 || outputTokens < 32 {
		return "ignored", "insufficient_output_tokens", 0, outputTokens
	}
	speed := float64(outputTokens) * 1000 / float64(generationMS)
	if config.FailClosed && generationMS < config.MinGenerationMS && speed >= config.SoftTPS {
		return "hard", "buffered_burst", speed, outputTokens
	}
	if speed >= config.HardTPS {
		return "hard", "hard_tps", speed, outputTokens
	}
	if speed >= config.SoftTPS {
		return "soft", "soft_tps", speed, outputTokens
	}
	return "healthy", "within_threshold", speed, outputTokens
}

// State is versioned because it is read directly by the backend admin API.
type State struct {
	Version            int                   `json:"version"`
	StartedAt          float64               `json:"started_at"`
	UpdatedAt          float64               `json:"updated_at"`
	LastActiveCycleAt  float64               `json:"last_active_cycle_at"`
	LastPassivePollAt  float64               `json:"last_passive_poll_at"`
	Guard              guardMetadata         `json:"guard"`
	ProtectedNodeIDs   []string              `json:"protected_node_ids"`
	Nodes              map[string]*NodeState `json:"nodes"`
	RecentEvents       []map[string]any      `json:"recent_events"`
	Statistics         statistics            `json:"statistics"`
	PassiveInitialized bool                  `json:"passive_initialized"`
	SeenAuditIDs       []string              `json:"seen_audit_ids"`
}

type guardMetadata struct {
	Mode                    string   `json:"mode"`
	Model                   string   `json:"model"`
	NodeIDs                 []string `json:"node_ids"`
	ActiveIntervalSeconds   int      `json:"active_interval_seconds"`
	PassivePollSeconds      int      `json:"passive_poll_seconds"`
	SoftTPS                 float64  `json:"soft_tps"`
	HardTPS                 float64  `json:"hard_tps"`
	ConsecutiveSoft         int      `json:"consecutive_soft"`
	ConsecutiveErrors       int      `json:"consecutive_errors"`
	QuarantineSeconds       int      `json:"quarantine_seconds"`
	NoAccountBackoffSeconds int      `json:"no_account_backoff_seconds"`
	MinHealthyNodes         int      `json:"min_healthy_nodes"`
	MaxOutputTokens         int      `json:"max_output_tokens"`
	FailClosed              bool     `json:"fail_closed"`
	MinGenerationMS         int      `json:"min_generation_ms"`
	RotatableNodeIDs        []string `json:"rotatable_node_ids"`
	Prompt                  string   `json:"prompt"`
	Expected                string   `json:"expected"`
}

type NodeState struct {
	ActiveSoftStrikes  int     `json:"active_soft_strikes"`
	PassiveSoftStrikes int     `json:"passive_soft_strikes"`
	ErrorStrikes       int     `json:"error_strikes"`
	QuarantinedUntil   float64 `json:"quarantined_until"`
	DisabledByGuard    bool    `json:"disabled_by_guard"`
	LastReason         string  `json:"last_reason"`
	LastProbeAt        float64 `json:"last_probe_at"`
	LastObservedAt     float64 `json:"last_observed_at"`
	LastSource         string  `json:"last_source"`
	LastClassification string  `json:"last_classification"`
	LastOutputTPS      float64 `json:"last_output_tps"`
	LastOutputTokens   int     `json:"last_output_tokens"`
	LastFirstTokenMS   int     `json:"last_first_token_ms"`
	LastDurationMS     int     `json:"last_duration_ms"`
	LastRotationAt     float64 `json:"last_rotation_at"`
	LastRotationExitIP string  `json:"last_rotation_exit_ip"`
	RotationFailures   int     `json:"rotation_failures"`
	LastNoAccountLogAt float64 `json:"last_no_account_log_at"`
	QuarantinePending  bool    `json:"quarantine_pending"`

	// Legacy fields allow one-time migration from the Python state schema.
	LegacySoftStrikes   int     `json:"soft_strikes,omitempty"`
	LegacyVisibleTPS    float64 `json:"last_visible_tps,omitempty"`
	LegacyVisibleTokens int     `json:"last_visible_tokens,omitempty"`
}

type statistics struct {
	StartedAt float64        `json:"started_at"`
	Active    detectionStats `json:"active"`
	Passive   detectionStats `json:"passive"`
	Actions   actionStats    `json:"actions"`
}

type detectionStats struct {
	Total        int64 `json:"total"`
	Healthy      int64 `json:"healthy"`
	Soft         int64 `json:"soft"`
	Hard         int64 `json:"hard"`
	Errors       int64 `json:"errors"`
	OutputTokens int64 `json:"output_tokens"`
	LegacyTokens int64 `json:"visible_tokens,omitempty"`
}

type actionStats struct {
	Quarantined int64 `json:"quarantined"`
	Restored    int64 `json:"restored"`
	Suppressed  int64 `json:"suppressed"`
}

func nowSeconds() float64 {
	return float64(time.Now().UnixNano()) / float64(time.Second)
}

func defaultNodeState() *NodeState {
	return &NodeState{}
}

func (s *State) ensureStatistics() error {
	if s.Statistics.StartedAt == 0 {
		s.Statistics.StartedAt = nowSeconds()
	}
	for _, group := range []*detectionStats{&s.Statistics.Active, &s.Statistics.Passive} {
		if group.OutputTokens == 0 && group.LegacyTokens != 0 {
			group.OutputTokens = group.LegacyTokens
		}
		group.LegacyTokens = 0
		if group.Total < 0 || group.Healthy < 0 || group.Soft < 0 || group.Hard < 0 || group.Errors < 0 || group.OutputTokens < 0 {
			return errors.New("invalid quality guard statistics")
		}
	}
	if s.Statistics.Actions.Quarantined < 0 || s.Statistics.Actions.Restored < 0 || s.Statistics.Actions.Suppressed < 0 {
		return errors.New("invalid quality guard statistics")
	}
	return nil
}

func loadState(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{Version: 1, Nodes: map[string]*NodeState{}, PassiveInitialized: false, SeenAuditIDs: []string{}}, nil
		}
		return State{}, fmt.Errorf("cannot read state file: %T", err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, fmt.Errorf("cannot read state file: %T", err)
	}
	if state.Version != 1 || state.Nodes == nil {
		return State{}, errors.New("unsupported state file format")
	}
	if state.SeenAuditIDs == nil {
		state.SeenAuditIDs = []string{}
	}
	if state.RecentEvents == nil {
		state.RecentEvents = []map[string]any{}
	}
	if state.LastActiveCycleAt == 0 {
		for _, node := range state.Nodes {
			if node != nil && node.LastProbeAt > state.LastActiveCycleAt {
				state.LastActiveCycleAt = node.LastProbeAt
			}
		}
	}
	if err := state.ensureStatistics(); err != nil {
		return State{}, err
	}
	return state, nil
}

func saveState(path string, state State) error {
	directory := path
	if index := strings.LastIndexByte(path, '/'); index >= 0 {
		directory = path[:index]
	}
	if directory == "" {
		directory = "."
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".state-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func appendStateEvent(state *State, event string, fields map[string]any) {
	value := make(map[string]any, len(fields)+2)
	value["ts"] = nowSeconds()
	value["event"] = event
	for key, field := range fields {
		value[key] = field
	}
	state.RecentEvents = append(state.RecentEvents, value)
	if len(state.RecentEvents) > 100 {
		state.RecentEvents = state.RecentEvents[len(state.RecentEvents)-100:]
	}
}

func logEvent(event string, fields map[string]any) {
	value := make(map[string]any, len(fields)+2)
	value["ts"] = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	value["event"] = event
	for key, field := range fields {
		value[key] = field
	}
	data, _ := json.Marshal(value)
	fmt.Println(string(data))
}

type Guard struct {
	config          *Config
	api             qualityAPI
	state           State
	resolvedNodeIDs []string
}

func newGuard(config *Config, api qualityAPI) (*Guard, error) {
	state, err := loadState(config.StateFile)
	if err != nil {
		return nil, err
	}
	if state.Nodes == nil {
		state.Nodes = make(map[string]*NodeState)
	}
	if state.StartedAt == 0 {
		state.StartedAt = nowSeconds()
	}
	if state.RecentEvents == nil {
		state.RecentEvents = []map[string]any{}
	}
	if err := state.ensureStatistics(); err != nil {
		return nil, err
	}
	guard := &Guard{config: config, api: api, state: state, resolvedNodeIDs: append([]string{}, config.NodeIDs...)}
	for nodeID := range guard.state.Nodes {
		guard.stateFor(nodeID)
	}
	if err := guard.save(); err != nil {
		return nil, err
	}
	return guard, nil
}

func (g *Guard) save() error {
	g.updateMetadata()
	return saveState(g.config.StateFile, g.state)
}

func (g *Guard) updateMetadata() {
	nodeIDs := g.config.NodeIDs
	if len(nodeIDs) == 0 {
		nodeIDs = g.resolvedNodeIDs
	}
	g.state.UpdatedAt = nowSeconds()
	g.state.Guard = guardMetadata{
		Mode:                    g.config.Mode,
		Model:                   g.config.Model,
		NodeIDs:                 append([]string{}, nodeIDs...),
		ActiveIntervalSeconds:   g.config.ActiveIntervalSeconds,
		PassivePollSeconds:      g.config.PassivePollSeconds,
		SoftTPS:                 g.config.SoftTPS,
		HardTPS:                 g.config.HardTPS,
		ConsecutiveSoft:         g.config.ConsecutiveSoft,
		ConsecutiveErrors:       g.config.ConsecutiveErrors,
		QuarantineSeconds:       g.config.QuarantineSeconds,
		NoAccountBackoffSeconds: g.config.NoAccountBackoffSeconds,
		MinHealthyNodes:         g.config.MinHealthyNodes,
		MaxOutputTokens:         g.config.MaxOutputTokens,
		FailClosed:              g.config.FailClosed,
		MinGenerationMS:         g.config.MinGenerationMS,
		RotatableNodeIDs:        append([]string{}, g.config.RotatableNodeIDs...),
		Prompt:                  g.config.Prompt,
		Expected:                g.config.Expected,
	}
}

func (g *Guard) stateFor(nodeID string) *NodeState {
	state := g.state.Nodes[nodeID]
	if state == nil {
		state = defaultNodeState()
		g.state.Nodes[nodeID] = state
	}
	if state.ActiveSoftStrikes == 0 && state.LegacySoftStrikes != 0 {
		state.ActiveSoftStrikes = state.LegacySoftStrikes
	}
	if state.LastOutputTPS == 0 && state.LegacyVisibleTPS != 0 {
		state.LastOutputTPS = state.LegacyVisibleTPS
	}
	if state.LastOutputTokens == 0 && state.LegacyVisibleTokens != 0 {
		state.LastOutputTokens = state.LegacyVisibleTokens
	}
	state.LegacySoftStrikes = 0
	state.LegacyVisibleTPS = 0
	state.LegacyVisibleTokens = 0
	return state
}

func (g *Guard) bump(group, field string, amount int64) {
	var target *detectionStats
	switch group {
	case "active":
		target = &g.state.Statistics.Active
	case "passive":
		target = &g.state.Statistics.Passive
	default:
		return
	}
	switch field {
	case "total":
		target.Total += amount
	case "healthy":
		target.Healthy += amount
	case "soft":
		target.Soft += amount
	case "hard":
		target.Hard += amount
	case "errors":
		target.Errors += amount
	case "output_tokens":
		target.OutputTokens += amount
	}
}

func (g *Guard) deferNoAccount(state *NodeState, node *Node, now float64, event string, fields map[string]any) {
	state.LastProbeAt = now
	state.LastReason = "probe_no_account"
	state.QuarantinedUntil = math.Max(state.QuarantinedUntil, now+float64(g.config.NoAccountBackoffSeconds))
	if state.LastNoAccountLogAt <= 0 || now-state.LastNoAccountLogAt >= float64(g.config.NoAccountBackoffSeconds) {
		state.LastNoAccountLogAt = now
		logFields := map[string]any{"node_id": node.ID, "node_name": node.Name, "reason": "probe_no_account"}
		for key, value := range fields {
			logFields[key] = value
		}
		logEvent(event, logFields)
	}
}

func (g *Guard) eligibleNodes(nodes []*Node, protected map[string]struct{}) []*Node {
	configured := make(map[string]struct{}, len(g.config.NodeIDs))
	for _, id := range g.config.NodeIDs {
		configured[id] = struct{}{}
	}
	result := make([]*Node, 0, len(nodes))
	for _, node := range nodes {
		if node == nil || node.ID == "" || !node.ProxyConfigured {
			continue
		}
		state := g.state.Nodes[node.ID]
		tracked := state != nil && state.DisabledByGuard
		if _, isProtected := protected[node.ID]; isProtected && !tracked {
			continue
		}
		if len(configured) > 0 {
			if _, ok := configured[node.ID]; !ok && !tracked {
				continue
			}
		}
		if node.Enabled || tracked {
			result = append(result, node)
		}
	}
	return result
}

func (g *Guard) canQuarantine(nodes []*Node, nodeID string) bool {
	enabled := 0
	targetEnabled := false
	for _, node := range nodes {
		if node == nil {
			continue
		}
		if node.Enabled {
			enabled++
			if node.ID == nodeID {
				targetEnabled = true
			}
		}
	}
	if g.config.FailClosed {
		return targetEnabled
	}
	return targetEnabled && enabled-1 >= g.config.MinHealthyNodes
}

func (g *Guard) shouldRotate(nodeID, reason string) bool {
	if g.config.RotationURL == "" {
		return false
	}
	rotatable := false
	for _, value := range g.config.RotatableNodeIDs {
		if value == nodeID {
			rotatable = true
			break
		}
	}
	if !rotatable {
		return false
	}
	switch reason {
	case "hard_tps", "soft_tps", "buffered_burst", "expected_marker_missing", "insufficient_output_tokens", "insufficient_generation_window", "probe_errors", "recovery_probe_error", "rotation_error":
		return true
	default:
		return false
	}
}

func probeAccountUnavailable(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == "egressQualityProbeNoAccount"
}

func (g *Guard) quarantine(nodes []*Node, node *Node, reason string, now float64) error {
	state := g.stateFor(node.ID)
	if !g.canQuarantine(nodes, node.ID) {
		g.state.Statistics.Actions.Suppressed++
		logEvent("quarantine_suppressed", map[string]any{"node_id": node.ID, "node_name": node.Name, "reason": reason, "minimum_healthy": g.config.MinHealthyNodes})
		return nil
	}
	previous := *state
	state.ActiveSoftStrikes = 0
	state.PassiveSoftStrikes = 0
	state.ErrorStrikes = 0
	state.QuarantinedUntil = now + float64(g.config.QuarantineSeconds)
	state.DisabledByGuard = true
	state.QuarantinePending = true
	state.LastReason = reason
	// Persist ownership before changing backend scheduling state.
	if err := g.save(); err != nil {
		return err
	}
	updated, err := g.api.SetEnabled(node.ID, false)
	if err != nil {
		*state = previous
		if saveErr := g.save(); saveErr != nil {
			return saveErr
		}
		logEvent("quarantine_failed", map[string]any{"node_id": node.ID, "node_name": node.Name, "reason": reason, "error_type": errorType(err)})
		return nil
	}
	if updated != 1 {
		*state = previous
		if saveErr := g.save(); saveErr != nil {
			return saveErr
		}
		logEvent("quarantine_not_applied", map[string]any{"node_id": node.ID, "node_name": node.Name, "reason": reason, "updated": updated})
		return nil
	}
	node.Enabled = false
	state.QuarantinePending = false
	g.state.Statistics.Actions.Quarantined++
	appendStateEvent(&g.state, "node_quarantined", map[string]any{"node_id": node.ID, "node_name": node.Name, "reason": reason})
	if err := g.save(); err != nil {
		return err
	}
	logEvent("node_quarantined", map[string]any{"node_id": node.ID, "node_name": node.Name, "reason": reason, "quarantine_seconds": g.config.QuarantineSeconds})
	if reason == "buffered_burst" {
		return g.recoverQuarantined(node, nowSeconds(), false, true)
	}
	if g.shouldRotate(node.ID, reason) {
		return g.recoverQuarantined(node, nowSeconds(), true, false)
	}
	return nil
}

func (g *Guard) recordProbe(node *Node, result qualityResult, classification, reason string, now float64) {
	state := g.stateFor(node.ID)
	tokens := outputTokens(result)
	speed := outputTPS(result)
	state.LastProbeAt = now
	state.LastObservedAt = now
	state.LastSource = "active"
	state.LastClassification = classification
	state.LastOutputTPS = round3(speed)
	state.LastOutputTokens = tokens
	state.LastFirstTokenMS = result.FirstTokenMS
	state.LastDurationMS = result.DurationMS
	state.ErrorStrikes = 0
	g.bump("active", classification, 1)
	g.bump("active", "output_tokens", int64(tokens))
	switch classification {
	case "healthy":
		state.ActiveSoftStrikes = 0
		state.PassiveSoftStrikes = 0
	case "soft":
		state.ActiveSoftStrikes++
	default:
		state.ActiveSoftStrikes = g.config.ConsecutiveSoft
	}
	logEvent("quality_probe_completed", map[string]any{
		"node_id": node.ID, "node_name": node.Name, "classification": classification, "reason": reason,
		"output_tps": round3(speed), "output_tokens": tokens, "first_token_ms": result.FirstTokenMS,
		"duration_ms": result.DurationMS, "chunk_count": result.ChunkCount, "expected_matched": result.ExpectedMatched,
	})
}

func (g *Guard) probeActive(nodes []*Node, node *Node, now float64, trigger string) error {
	state := g.stateFor(node.ID)
	if state.LastReason == "probe_no_account" && now < state.QuarantinedUntil {
		return nil
	}
	g.bump("active", "total", 1)
	result, err := g.api.QualityTest(node.ID)
	if err != nil {
		if probeAccountUnavailable(err) {
			g.deferNoAccount(state, node, now, "quality_probe_deferred", map[string]any{"trigger": trigger})
			return nil
		}
		g.bump("active", "errors", 1)
		state.ErrorStrikes++
		state.LastProbeAt = now
		logEvent("quality_probe_failed", map[string]any{"node_id": node.ID, "node_name": node.Name, "trigger": trigger, "error_type": errorType(err), "strikes": state.ErrorStrikes})
		if trigger == "scheduled" && state.ErrorStrikes >= g.config.ConsecutiveErrors {
			return g.quarantine(nodes, node, "probe_errors", now)
		}
		return nil
	}
	classification, reason := classifyResult(result, g.config)
	g.recordProbe(node, result, classification, reason, now)
	if classification == "hard" || (classification == "soft" && g.config.FailClosed) || state.ActiveSoftStrikes >= g.config.ConsecutiveSoft {
		return g.quarantine(nodes, node, reason, now)
	}
	return nil
}

func (g *Guard) recoverQuarantined(node *Node, now float64, rotate, rotateOnFailure bool) error {
	state := g.stateFor(node.ID)
	if rotate {
		rotation, err := g.api.RotateNode(node.ID, node.ExitIP)
		if err != nil {
			state.RotationFailures++
			state.QuarantinedUntil = now + float64(g.config.QuarantineSeconds)
			state.LastReason = "rotation_error"
			logEvent("node_rotation_failed", map[string]any{"node_id": node.ID, "node_name": node.Name, "error_type": errorType(err)})
			return nil
		}
		state.LastRotationAt = nowSeconds()
		state.LastRotationExitIP = rotation.NewExitIP
		state.RotationFailures = 0
		appendStateEvent(&g.state, "node_rotated", map[string]any{"node_id": node.ID, "node_name": node.Name, "exit_ip": rotation.NewExitIP})
		logEvent("node_rotated", map[string]any{"node_id": node.ID, "node_name": node.Name, "exit_ip": rotation.NewExitIP})
	}
	connectivityStatus := "unknown"
	if connectivity, err := g.api.ConnectivityTest(node.ID); err != nil {
		connectivityStatus = "error"
		logEvent("recovery_connectivity_probe_failed", map[string]any{"node_id": node.ID, "node_name": node.Name, "error_type": errorType(err)})
	} else if value, ok := connectivity["status"].(string); ok && value != "" {
		connectivityStatus = value
	}
	g.bump("active", "total", 1)
	result, err := g.api.QualityTest(node.ID)
	if err != nil {
		if probeAccountUnavailable(err) {
			g.deferNoAccount(state, node, now, "recovery_probe_deferred", nil)
			return nil
		}
		g.bump("active", "errors", 1)
		state.QuarantinedUntil = now + float64(g.config.QuarantineSeconds)
		state.LastReason = "recovery_probe_error"
		logEvent("recovery_probe_failed", map[string]any{"node_id": node.ID, "node_name": node.Name, "error_type": errorType(err)})
		return nil
	}
	classification, reason := classifyResult(result, g.config)
	g.recordProbe(node, result, classification, reason, now)
	if classification != "healthy" {
		state.QuarantinedUntil = now + float64(g.config.QuarantineSeconds)
		state.LastReason = reason
		logEvent("quarantine_extended", map[string]any{"node_id": node.ID, "node_name": node.Name, "reason": reason})
		if rotateOnFailure && g.shouldRotate(node.ID, reason) {
			return g.recoverQuarantined(node, nowSeconds(), true, false)
		}
		return nil
	}
	updated, err := g.api.SetEnabled(node.ID, true)
	if err != nil {
		logEvent("restore_failed", map[string]any{"node_id": node.ID, "node_name": node.Name, "error_type": errorType(err)})
		return nil
	}
	if updated != 1 {
		logEvent("restore_not_applied", map[string]any{"node_id": node.ID, "node_name": node.Name, "updated": updated})
		return nil
	}
	state.ActiveSoftStrikes = 0
	state.PassiveSoftStrikes = 0
	state.ErrorStrikes = 0
	state.QuarantinedUntil = 0
	state.DisabledByGuard = false
	state.QuarantinePending = false
	state.LastReason = ""
	node.Enabled = true
	g.state.Statistics.Actions.Restored++
	appendStateEvent(&g.state, "node_restored", map[string]any{"node_id": node.ID, "node_name": node.Name, "reason": "quality_probe_healthy"})
	logEvent("node_restored", map[string]any{"node_id": node.ID, "node_name": node.Name, "connectivity_status": connectivityStatus})
	return nil
}

func (g *Guard) probeQuarantined(node *Node, now float64) error {
	state := g.stateFor(node.ID)
	if now < state.QuarantinedUntil {
		return nil
	}
	reason := state.LastReason
	return g.recoverQuarantined(node, now, g.shouldRotate(node.ID, reason) && reason != "buffered_burst", reason == "buffered_burst")
}

func (g *Guard) prepareNodes(now float64) ([]*Node, []*Node, map[string]struct{}, error) {
	allNodes, err := g.api.ListNodes()
	if err != nil {
		return nil, nil, nil, err
	}
	protected, err := g.api.FixedFallbackNodeIDs()
	if err != nil {
		return nil, nil, nil, err
	}
	previous := make(map[string]struct{}, len(g.state.ProtectedNodeIDs))
	for _, id := range g.state.ProtectedNodeIDs {
		previous[id] = struct{}{}
	}
	if !sameStringSet(protected, previous) {
		g.state.ProtectedNodeIDs = sortedKeys(protected)
		for _, id := range sortedDifference(protected, previous) {
			logEvent("fixed_fallback_node_skipped", map[string]any{"node_id": id})
		}
	}
	if len(g.config.NodeIDs) == 0 {
		g.resolvedNodeIDs = g.resolvedNodeIDs[:0]
		for _, node := range allNodes {
			if node != nil && node.ID != "" && node.ProxyConfigured {
				if _, ok := protected[node.ID]; !ok {
					g.resolvedNodeIDs = append(g.resolvedNodeIDs, node.ID)
				}
			}
		}
	}
	nodes := g.eligibleNodes(allNodes, protected)
	present := make(map[string]struct{}, len(allNodes))
	managed := make(map[string]struct{}, len(nodes))
	for _, node := range allNodes {
		if node != nil && node.ID != "" {
			present[node.ID] = struct{}{}
		}
	}
	for _, node := range nodes {
		if node != nil && node.ID != "" {
			managed[node.ID] = struct{}{}
		}
	}
	for id, state := range g.state.Nodes {
		_, isPresent := present[id]
		_, isManaged := managed[id]
		if !isPresent || (!isManaged && (state == nil || !state.DisabledByGuard)) {
			delete(g.state.Nodes, id)
		}
	}
	skip := make(map[string]struct{})
	if len(nodes) == 0 {
		logEvent("no_eligible_nodes", nil)
		return allNodes, nodes, skip, nil
	}
	for _, node := range nodes {
		state := g.stateFor(node.ID)
		if state.QuarantinePending {
			if !node.Enabled {
				// The process may have stopped after the backend disable but before
				// the final state write. The disabled node is already owned by us.
				state.QuarantinePending = false
			} else {
				updated, err := g.api.SetEnabled(node.ID, false)
				if err != nil {
					return nil, nil, nil, err
				}
				if updated != 1 {
					logEvent("quarantine_reconcile_failed", map[string]any{"node_id": node.ID, "node_name": node.Name, "updated": updated})
					skip[node.ID] = struct{}{}
					continue
				}
				node.Enabled = false
				state.QuarantinePending = false
				logEvent("quarantine_reconciled", map[string]any{"node_id": node.ID, "node_name": node.Name})
			}
		}
		if state.DisabledByGuard && node.Enabled {
			if g.config.FailClosed {
				updated, err := g.api.SetEnabled(node.ID, false)
				if err != nil {
					return nil, nil, nil, err
				}
				if updated == 1 {
					node.Enabled = false
					state.QuarantinePending = false
					state.QuarantinedUntil = now + float64(g.config.QuarantineSeconds)
					logEvent("operator_reenable_requires_probe", map[string]any{"node_id": node.ID, "node_name": node.Name})
					if err := g.recoverQuarantined(node, now, g.shouldRotate(node.ID, state.LastReason) && state.LastReason != "buffered_burst", state.LastReason == "buffered_burst"); err != nil {
						return nil, nil, nil, err
					}
				}
				skip[node.ID] = struct{}{}
				continue
			}
			state.ActiveSoftStrikes = 0
			state.PassiveSoftStrikes = 0
			state.ErrorStrikes = 0
			state.QuarantinedUntil = 0
			state.DisabledByGuard = false
			state.QuarantinePending = false
			state.LastReason = ""
			logEvent("operator_reenabled_node", map[string]any{"node_id": node.ID, "node_name": node.Name})
			skip[node.ID] = struct{}{}
			continue
		}
		if state.DisabledByGuard {
			skip[node.ID] = struct{}{}
			if err := g.probeQuarantined(node, now); err != nil {
				return nil, nil, nil, err
			}
		}
	}
	return allNodes, nodes, skip, nil
}

func (g *Guard) runActiveCycle() error {
	now := nowSeconds()
	allNodes, nodes, skip, err := g.prepareNodes(now)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		state := g.stateFor(node.ID)
		if _, skipped := skip[node.ID]; !skipped && node.Enabled && !state.DisabledByGuard {
			if err := g.probeActive(allNodes, node, now, "scheduled"); err != nil {
				return err
			}
		}
		if err := g.save(); err != nil {
			return err
		}
	}
	g.state.LastActiveCycleAt = nowSeconds()
	return g.save()
}

func (g *Guard) fetchNewAudits() ([]auditValue, error) {
	known := make(map[string]struct{}, len(g.state.SeenAuditIDs))
	for _, id := range g.state.SeenAuditIDs {
		known[id] = struct{}{}
	}
	fetchedIDs := make([]string, 0)
	collected := make([]auditValue, 0)
	cursor := ""
	reachedKnown := false
	for page := 0; page < passiveMaxPages; page++ {
		value, err := g.api.ListAudits(cursor)
		if err != nil {
			return nil, err
		}
		if len(value.Items) == 0 {
			break
		}
		for _, item := range value.Items {
			auditID := item.ID
			if auditID == "" {
				auditID = item.RequestID
			}
			if auditID == "" {
				continue
			}
			fetchedIDs = append(fetchedIDs, auditID)
			if _, ok := known[auditID]; ok {
				reachedKnown = true
				break
			}
			collected = append(collected, item)
		}
		if reachedKnown || !value.HasMore {
			break
		}
		cursor = value.NextCursor
		if cursor == "" {
			break
		}
	}
	combined := make([]string, 0, len(fetchedIDs)+len(g.state.SeenAuditIDs))
	seen := make(map[string]struct{})
	for _, id := range append(append([]string{}, fetchedIDs...), g.state.SeenAuditIDs...) {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		combined = append(combined, id)
		if len(combined) >= 2000 {
			break
		}
	}
	g.state.SeenAuditIDs = combined
	if !g.state.PassiveInitialized {
		g.state.PassiveInitialized = true
		logEvent("passive_baseline_initialized", map[string]any{"audit_count": len(fetchedIDs)})
		return []auditValue{}, nil
	}
	if len(collected) > 0 && !reachedKnown && len(known) > 0 {
		logEvent("passive_audit_gap", map[string]any{"collected": len(collected), "max_pages": passiveMaxPages})
	}
	for left, right := 0, len(collected)-1; left < right; left, right = left+1, right-1 {
		collected[left], collected[right] = collected[right], collected[left]
	}
	return collected, nil
}

func (g *Guard) recordPassiveAudit(allNodes []*Node, node *Node, value auditValue, now float64) error {
	state := g.stateFor(node.ID)
	classification, reason, speed, tokens := classifyAudit(value, g.config)
	if classification == "ignored" {
		return nil
	}
	g.bump("passive", "total", 1)
	g.bump("passive", classification, 1)
	g.bump("passive", "output_tokens", int64(tokens))
	state.LastObservedAt = now
	state.LastSource = "passive"
	state.LastClassification = classification
	state.LastOutputTPS = round3(speed)
	state.LastOutputTokens = tokens
	if value.FirstTokenMS != nil {
		state.LastFirstTokenMS = *value.FirstTokenMS
	} else {
		state.LastFirstTokenMS = 0
	}
	state.LastDurationMS = value.DurationMS
	if classification == "healthy" {
		state.PassiveSoftStrikes = 0
		return nil
	}
	if classification == "soft" {
		state.PassiveSoftStrikes++
	} else {
		state.PassiveSoftStrikes = g.config.ConsecutiveSoft
	}
	appendStateEvent(&g.state, "passive_audit_anomaly", map[string]any{"node_id": node.ID, "node_name": node.Name, "reason": reason, "classification": classification, "output_tps": round3(speed)})
	firstTokenMS := 0
	if value.FirstTokenMS != nil {
		firstTokenMS = *value.FirstTokenMS
	}
	logEvent("passive_audit_anomaly", map[string]any{"request_id": value.RequestID, "node_id": node.ID, "node_name": node.Name, "classification": classification, "reason": reason, "output_tps": round3(speed), "output_tokens": tokens, "first_token_ms": firstTokenMS, "duration_ms": value.DurationMS, "strikes": state.PassiveSoftStrikes})
	if classification == "hard" || g.config.FailClosed {
		return g.quarantine(allNodes, node, reason, now)
	}
	return g.probeActive(allNodes, node, now, "passive_confirmation")
}

func (g *Guard) runPassiveCycle() error {
	now := nowSeconds()
	g.state.LastPassivePollAt = now
	allNodes, nodes, _, err := g.prepareNodes(now)
	if err != nil {
		return err
	}
	nodeByID := make(map[string]*Node, len(nodes))
	for _, node := range nodes {
		nodeByID[node.ID] = node
	}
	audits, err := g.fetchNewAudits()
	if err != nil {
		return err
	}
	for _, value := range audits {
		if value.QualityProbe {
			continue
		}
		node := nodeByID[value.EgressNodeID]
		if node == nil || !node.Enabled {
			continue
		}
		if err := g.recordPassiveAudit(allNodes, node, value, now); err != nil {
			return err
		}
	}
	return g.save()
}

func (g *Guard) runCycle() error {
	return g.runActiveCycle()
}

func sameStringSet(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for key := range a {
		if _, ok := b[key]; !ok {
			return false
		}
	}
	return true
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedDifference(a, b map[string]struct{}) []string {
	result := make([]string, 0)
	for value := range a {
		if _, ok := b[value]; !ok {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func round3(value float64) float64 {
	return math.Round(value*1000) / 1000
}

func errorType(err error) string {
	if err == nil {
		return ""
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return "ApiError"
	}
	return fmt.Sprintf("%T", err)
}

func acquireLock(path string) (*os.File, error) {
	directory := path
	if index := strings.LastIndexByte(path, '/'); index >= 0 {
		directory = path[:index]
	}
	if directory == "" {
		directory = "."
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errors.New("another quality guard instance is already running")
		}
		return nil, err
	}
	return file, nil
}

func run(args []string) int {
	flags := flag.NewFlagSet("grok2api-egress-quality-guard", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	once := flags.Bool("once", false, "run one cycle for each detector enabled by the selected mode")
	checkConfig := flags.Bool("check-config", false, "validate config.yaml bootstrap and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	config, err := loadConfig(bootstrapPath)
	if errors.Is(err, errGuardDisabled) {
		fmt.Println(err)
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		return 2
	}
	reloader := newRuntimeReloader(config)
	config, _, err = reloader.reload(true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		return 2
	}
	if *checkConfig {
		fmt.Println("configuration is valid")
		return 0
	}
	lock, err := acquireLock(config.LockFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	defer lock.Close()
	api := newAPIClient(config)
	guard, err := newGuard(config, api)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quality guard initialization failed: %v\n", err)
		return 1
	}
	stopping := make(chan os.Signal, 1)
	signal.Notify(stopping, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(stopping)
	lastActiveAt := guard.state.LastActiveCycleAt
	activeDelay := math.Max(0, lastActiveAt+float64(config.ActiveIntervalSeconds)-nowSeconds())
	nextActive := time.Now().Add(time.Duration(activeDelay * float64(time.Second)))
	if *once {
		nextActive = time.Time{}
	}
	nextPassive := time.Time{}
	logEvent("guard_started", map[string]any{"mode": config.Mode, "active_interval_seconds": config.ActiveIntervalSeconds, "passive_poll_seconds": config.PassivePollSeconds, "node_count": len(config.NodeIDs), "model": config.Model})
	for {
		select {
		case <-stopping:
			logEvent("guard_stopped", nil)
			return 0
		default:
		}
		now := time.Now()
		nextConfig, changed, runtimeErr := reloader.reload(false)
		if runtimeErr != nil {
			logEvent("runtime_config_rejected", map[string]any{"error_type": errorType(runtimeErr)})
		} else if changed {
			previousMode := config.Mode
			config = nextConfig
			guard.config = config
			api.config = config
			lastActiveAt = guard.state.LastActiveCycleAt
			activeDelay = math.Max(0, lastActiveAt+float64(config.ActiveIntervalSeconds)-nowSeconds())
			nextActive = time.Now().Add(time.Duration(activeDelay * float64(time.Second)))
			nextPassive = time.Time{}
			if err := guard.save(); err != nil {
				logEvent("runtime_config_save_failed", map[string]any{"error_type": errorType(err)})
			}
			logEvent("runtime_config_reloaded", map[string]any{"previous_mode": previousMode, "mode": config.Mode})
		}
		activeEnabled := config.Mode == "active" || config.Mode == "hybrid"
		passiveEnabled := config.Mode == "passive" || config.Mode == "hybrid"
		if passiveEnabled && (nextPassive.IsZero() || !now.Before(nextPassive)) {
			if err := guard.runPassiveCycle(); err != nil {
				logEvent("passive_cycle_failed", map[string]any{"error_type": errorType(err)})
			}
			nextPassive = time.Now().Add(time.Duration(config.PassivePollSeconds) * time.Second)
		}
		if activeEnabled && (nextActive.IsZero() || !now.Before(nextActive)) {
			if err := guard.runActiveCycle(); err != nil {
				logEvent("active_cycle_failed", map[string]any{"error_type": errorType(err)})
			}
			jitter := 0
			if jitterSeconds > 0 {
				var randomByte [1]byte
				if _, randomErr := rand.Read(randomByte[:]); randomErr == nil {
					jitter = int(randomByte[0])%(2*jitterSeconds+1) - jitterSeconds
				}
			}
			delay := maxInt(60, config.ActiveIntervalSeconds+jitter)
			nextActive = time.Now().Add(time.Duration(delay) * time.Second)
		}
		if *once {
			logEvent("guard_stopped", nil)
			return 0
		}
		deadlines := make([]time.Time, 0, 2)
		if passiveEnabled {
			deadlines = append(deadlines, nextPassive)
		}
		if activeEnabled {
			deadlines = append(deadlines, nextActive)
		}
		delay := time.Second
		if len(deadlines) > 0 {
			next := deadlines[0]
			for _, deadline := range deadlines[1:] {
				if deadline.Before(next) {
					next = deadline
				}
			}
			if remaining := time.Until(next); remaining > 100*time.Millisecond {
				delay = remaining
			} else {
				delay = 100 * time.Millisecond
			}
			if delay > time.Second {
				delay = time.Second
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-stopping:
			if !timer.Stop() {
				<-timer.C
			}
			logEvent("guard_stopped", nil)
			return 0
		case <-timer.C:
		}
	}
}

func main() {
	os.Exit(run(os.Args[1:]))
}
