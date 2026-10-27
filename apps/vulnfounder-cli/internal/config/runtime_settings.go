package config

import "strings"

// SourceLocatorSettings is the non-secret OpenGrok configuration exposed by
// the Web settings page.  It mirrors the Python source_locator schema while
// deliberately omitting probe results and bearer token values.
type SourceLocatorSettings struct {
	Enabled        bool
	TargetRevision string
	BaseURL        string
	Project        string
	APIPrefix      string
	TimeoutSeconds float64
	MaxRetries     int
	VerifyTLS      bool
	AuthMode       string
	TokenEnv       string
}

func defaultSourceLocatorSettings() SourceLocatorSettings {
	return SourceLocatorSettings{
		Enabled:        true,
		TargetRevision: "OpenHarmony-7.0-Release",
		Project:        "*",
		APIPrefix:      "/api/v1",
		TimeoutSeconds: 20,
		MaxRetries:     1,
		VerifyTLS:      true,
		AuthMode:       "none",
	}
}

// GetSourceLocatorSettings returns a secret-free view of the persisted
// source_locator section. Missing fields receive the same defaults as the
// Python parser, so the UI remains useful on a first run.
func (c *Config) GetSourceLocatorSettings() SourceLocatorSettings {
	out := defaultSourceLocatorSettings()
	if c == nil || c.raw == nil {
		return out
	}
	root, ok := c.raw["source_locator"].(map[string]any)
	if !ok {
		return out
	}
	if value, ok := root["enabled"].(bool); ok {
		out.Enabled = value
	}
	if value, ok := root["target_revision"].(string); ok {
		out.TargetRevision = strings.TrimSpace(value)
	}
	opengrok, ok := root["opengrok"].(map[string]any)
	if !ok {
		return out
	}
	if value, ok := opengrok["base_url"].(string); ok {
		out.BaseURL = strings.TrimSpace(value)
	}
	if value, ok := opengrok["project"].(string); ok {
		out.Project = strings.TrimSpace(value)
	}
	if value, ok := opengrok["api_prefix"].(string); ok {
		out.APIPrefix = strings.TrimSpace(value)
	}
	if value, ok := opengrok["timeout_seconds"].(float64); ok && value > 0 {
		out.TimeoutSeconds = value
	}
	if value, ok := opengrok["max_retries"].(float64); ok && value >= 0 {
		out.MaxRetries = int(value)
	}
	if value, ok := opengrok["verify_tls"].(bool); ok {
		out.VerifyTLS = value
	}
	if auth, ok := opengrok["auth"].(map[string]any); ok {
		if value, ok := auth["mode"].(string); ok {
			out.AuthMode = strings.TrimSpace(value)
		}
		if value, ok := auth["token_env"].(string); ok {
			out.TokenEnv = strings.TrimSpace(value)
		}
	}
	return out
}

// WriteSourceLocatorSettings updates only the editable OpenGrok fields. The
// manifest, GitCode policy, last_probe and unknown sibling fields are kept.
func (c *Config) WriteSourceLocatorSettings(settings SourceLocatorSettings) {
	if c.raw == nil {
		c.raw = map[string]any{}
	}
	root, ok := c.raw["source_locator"].(map[string]any)
	if !ok {
		root = map[string]any{}
		c.raw["source_locator"] = root
	}
	root["enabled"] = settings.Enabled
	if strings.TrimSpace(settings.TargetRevision) == "" {
		delete(root, "target_revision")
	} else {
		root["target_revision"] = strings.TrimSpace(settings.TargetRevision)
	}
	opengrok, ok := root["opengrok"].(map[string]any)
	if !ok {
		opengrok = map[string]any{}
		root["opengrok"] = opengrok
	}
	opengrok["base_url"] = strings.TrimRight(strings.TrimSpace(settings.BaseURL), "/")
	opengrok["project"] = strings.TrimSpace(settings.Project)
	opengrok["api_prefix"] = strings.TrimRight("/"+strings.TrimLeft(strings.TrimSpace(settings.APIPrefix), "/"), "/")
	opengrok["timeout_seconds"] = settings.TimeoutSeconds
	opengrok["max_retries"] = settings.MaxRetries
	opengrok["verify_tls"] = settings.VerifyTLS
	auth, ok := opengrok["auth"].(map[string]any)
	if !ok {
		auth = map[string]any{}
		opengrok["auth"] = auth
	}
	auth["mode"] = strings.TrimSpace(settings.AuthMode)
	if strings.TrimSpace(settings.TokenEnv) == "" {
		delete(auth, "token_env")
	} else {
		auth["token_env"] = strings.TrimSpace(settings.TokenEnv)
	}
}
