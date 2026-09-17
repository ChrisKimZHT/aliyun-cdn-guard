package config

import (
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type SLSConfig struct {
	Endpoint             string
	Region               string
	Project              string
	Logstore             string
	ConsumerGroup        string
	ConsumerName         string
	CursorPosition       string
	FetchIntervalSeconds int
}

type CDNConfig struct {
	Region              string
	Endpoint            string
	Domains             []string
	IPACLXForwarded     string
	SyncIntervalSeconds int
	DryRun              bool
}

type DimensionConfig struct{ Enabled bool }

type URIConfig struct {
	Enabled      bool
	QueryMode    string
	IgnoredNames map[string]struct{}
}

type DetectionConfig struct {
	Threshold        int
	WindowSeconds    int
	RetentionSeconds int
	UA               DimensionConfig
	URI              URIConfig
}

type PenaltyConfig struct {
	BaseDurationSeconds int
	Multiplier          float64
	MaxDurationSeconds  int
}

type WhitelistConfig struct {
	Domains    map[string]struct{}
	IPNetworks []netip.Prefix
	UARegexes  []*regexp.Regexp
	URIRegexes []*regexp.Regexp
}

type Config struct {
	SLS                   SLSConfig
	CDN                   CDNConfig
	Detection             DetectionConfig
	Penalty               PenaltyConfig
	Whitelist             WhitelistConfig
	PermanentBlocklist    map[string][]string
	StoragePath           string
	BlockLogPath          string
	LogLevel              string
	ReportIntervalSeconds int
}

type rawConfig struct {
	SLS struct {
		Endpoint                                    string `yaml:"endpoint"`
		Region                                      string `yaml:"region"`
		Project                                     string `yaml:"project"`
		Logstore                                    string `yaml:"logstore"`
		ConsumerGroup, ConsumerName, CursorPosition string `yaml:"-"`
		ConsumerGroupValue                          any    `yaml:"consumer_group"`
		ConsumerNameValue                           any    `yaml:"consumer_name"`
		CursorPositionValue                         any    `yaml:"cursor_position"`
		FetchInterval                               any    `yaml:"fetch_interval_seconds"`
	} `yaml:"sls"`
	CDN struct {
		Region          string `yaml:"region"`
		Endpoint        string `yaml:"endpoint"`
		Domains         []any  `yaml:"domains"`
		IPACLXForwarded any    `yaml:"ip_acl_xfwd"`
		SyncInterval    any    `yaml:"sync_interval_seconds"`
		DryRun          any    `yaml:"dry_run"`
	} `yaml:"cdn"`
	Detection struct {
		Threshold        any `yaml:"threshold"`
		WindowSeconds    any `yaml:"window_seconds"`
		RetentionSeconds any `yaml:"retention_seconds"`
		UA               struct {
			Enabled any `yaml:"enabled"`
		} `yaml:"ua"`
		URI struct {
			Enabled         any `yaml:"enabled"`
			QueryParameters struct {
				Mode         any   `yaml:"mode"`
				IgnoredNames []any `yaml:"ignored_names"`
			} `yaml:"query_parameters"`
		} `yaml:"uri"`
	} `yaml:"detection"`
	Penalty struct {
		BaseDurationSeconds any `yaml:"base_duration_seconds"`
		Multiplier          any `yaml:"multiplier"`
		MaxDurationSeconds  any `yaml:"max_duration_seconds"`
	} `yaml:"penalty"`
	Whitelist struct {
		Domains    []any `yaml:"domains"`
		IPs        []any `yaml:"ips"`
		UARegexes  []any `yaml:"ua_regexes"`
		URIRegexes []any `yaml:"uri_regexes"`
	} `yaml:"whitelist"`
	PermanentBlocklist map[string][]any `yaml:"permanent_blocklist"`
	Storage            struct {
		Path any `yaml:"path"`
	} `yaml:"storage"`
	Logging struct {
		Level                 any `yaml:"level"`
		ReportIntervalSeconds any `yaml:"report_interval_seconds"`
		BlockLogPath          any `yaml:"block_log_path"`
	} `yaml:"logging"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config: %s: %w", path, err)
	}
	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}

	required := func(value, name string) (string, error) {
		value = strings.TrimSpace(value)
		if value == "" {
			return "", fmt.Errorf("%s is required", name)
		}
		return value, nil
	}
	endpoint, err := required(raw.SLS.Endpoint, "sls.endpoint")
	if err != nil {
		return nil, err
	}
	region, err := required(raw.SLS.Region, "sls.region")
	if err != nil {
		return nil, err
	}
	project, err := required(raw.SLS.Project, "sls.project")
	if err != nil {
		return nil, err
	}
	logstore, err := required(raw.SLS.Logstore, "sls.logstore")
	if err != nil {
		return nil, err
	}
	cdnRegion, err := required(raw.CDN.Region, "cdn.region")
	if err != nil {
		return nil, err
	}

	domains := uniqueLowerStrings(raw.CDN.Domains)
	if len(domains) == 0 {
		return nil, fmt.Errorf("cdn.domains must be a non-empty list")
	}
	domainSet := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		domainSet[d] = struct{}{}
	}

	ipACL := strings.ToLower(stringDefault(raw.CDN.IPACLXForwarded, "on"))
	if b, ok := raw.CDN.IPACLXForwarded.(bool); ok {
		if b {
			ipACL = "on"
		} else {
			ipACL = "off"
		}
	}
	if ipACL != "on" && ipACL != "off" && ipACL != "all" {
		return nil, fmt.Errorf("cdn.ip_acl_xfwd must be on, off, or all")
	}
	cursor := stringDefault(raw.SLS.CursorPositionValue, "end")
	if cursor != "end" && cursor != "begin" {
		if _, err := parseISOTime(cursor); err != nil {
			return nil, fmt.Errorf("sls.cursor_position must be end, begin, or an ISO datetime")
		}
	}

	threshold, err := intDefault(raw.Detection.Threshold, 1000)
	if err != nil {
		return nil, fmt.Errorf("detection.threshold: %w", err)
	}
	window, err := intDefault(raw.Detection.WindowSeconds, 60)
	if err != nil {
		return nil, fmt.Errorf("detection.window_seconds: %w", err)
	}
	retention, err := intDefault(raw.Detection.RetentionSeconds, max(window, 3600))
	if err != nil {
		return nil, fmt.Errorf("detection.retention_seconds: %w", err)
	}
	if threshold < 1 || window < 1 || retention < window {
		return nil, fmt.Errorf("threshold/window_seconds must be positive and retention_seconds >= window_seconds")
	}

	queryMode := stringDefault(raw.Detection.URI.QueryParameters.Mode, "keep")
	if queryMode != "keep" && queryMode != "ignore_all" && queryMode != "ignore_selected" {
		return nil, fmt.Errorf("detection.uri.query_parameters.mode must be keep, ignore_all, or ignore_selected")
	}
	ignored := make(map[string]struct{})
	for _, v := range raw.Detection.URI.QueryParameters.IgnoredNames {
		ignored[fmt.Sprint(v)] = struct{}{}
	}
	uaEnabled, err := boolDefault(raw.Detection.UA.Enabled, false)
	if err != nil {
		return nil, fmt.Errorf("detection.ua.enabled must be a boolean")
	}
	uriEnabled, err := boolDefault(raw.Detection.URI.Enabled, false)
	if err != nil {
		return nil, fmt.Errorf("detection.uri.enabled must be a boolean")
	}
	dryRun, err := boolDefault(raw.CDN.DryRun, true)
	if err != nil {
		return nil, fmt.Errorf("cdn.dry_run must be a boolean")
	}

	base, err := intDefault(raw.Penalty.BaseDurationSeconds, 600)
	if err != nil {
		return nil, err
	}
	multiplier, err := floatDefault(raw.Penalty.Multiplier, 2)
	if err != nil {
		return nil, err
	}
	maximum, err := intDefault(raw.Penalty.MaxDurationSeconds, 86400)
	if err != nil {
		return nil, err
	}
	if base < 1 || multiplier < 1 || maximum < base {
		return nil, fmt.Errorf("penalty requires base > 0, multiplier >= 1, and max >= base")
	}

	whitelistNetworks, err := parseNetworks(raw.Whitelist.IPs, "whitelist.ips")
	if err != nil {
		return nil, err
	}
	uaRegexes, err := compileRegexes(raw.Whitelist.UARegexes, "whitelist.ua_regexes")
	if err != nil {
		return nil, err
	}
	uriRegexes, err := compileRegexes(raw.Whitelist.URIRegexes, "whitelist.uri_regexes")
	if err != nil {
		return nil, err
	}
	permanent := make(map[string][]string)
	for domain, values := range raw.PermanentBlocklist {
		domain = strings.ToLower(domain)
		if _, ok := domainSet[domain]; !ok {
			return nil, fmt.Errorf("permanent_blocklist domain is not in cdn.domains: %s", domain)
		}
		networks, err := parseNetworks(values, "permanent_blocklist."+domain)
		if err != nil {
			return nil, err
		}
		for _, p := range networks {
			permanent[domain] = append(permanent[domain], expandedPrefix(p))
		}
	}

	configAbs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	baseDir := filepath.Dir(configAbs)
	storagePath, err := relativeTo(baseDir, stringDefault(raw.Storage.Path, "data/guard.db"))
	if err != nil {
		return nil, err
	}
	blockLogPath, err := relativeTo(baseDir, stringDefault(raw.Logging.BlockLogPath, "data/blocks.jsonl"))
	if err != nil {
		return nil, err
	}
	logLevel := strings.ToUpper(stringDefault(raw.Logging.Level, "INFO"))
	allowedLevels := map[string]bool{"TRACE": true, "DEBUG": true, "INFO": true, "SUCCESS": true, "WARNING": true, "ERROR": true, "CRITICAL": true}
	if !allowedLevels[logLevel] {
		return nil, fmt.Errorf("logging.level is invalid: %s", logLevel)
	}
	reportInterval, err := intDefault(raw.Logging.ReportIntervalSeconds, 60)
	if err != nil || reportInterval < 1 {
		return nil, fmt.Errorf("logging.report_interval_seconds must be positive")
	}
	fetchInterval, err := intDefault(raw.SLS.FetchInterval, 2)
	if err != nil {
		return nil, err
	}
	fetchInterval = max(1, fetchInterval)
	syncInterval, err := intDefault(raw.CDN.SyncInterval, 10)
	if err != nil {
		return nil, err
	}
	syncInterval = max(1, syncInterval)

	return &Config{
		SLS:                SLSConfig{endpoint, region, project, logstore, stringDefault(raw.SLS.ConsumerGroupValue, "aliyun-cdn-guard"), stringDefault(raw.SLS.ConsumerNameValue, ""), cursor, fetchInterval},
		CDN:                CDNConfig{cdnRegion, stringDefault(raw.CDN.Endpoint, "cdn.aliyuncs.com"), domains, ipACL, syncInterval, dryRun},
		Detection:          DetectionConfig{threshold, window, retention, DimensionConfig{uaEnabled}, URIConfig{uriEnabled, queryMode, ignored}},
		Penalty:            PenaltyConfig{base, multiplier, maximum},
		Whitelist:          WhitelistConfig{stringSet(raw.Whitelist.Domains, true), whitelistNetworks, uaRegexes, uriRegexes},
		PermanentBlocklist: permanent, StoragePath: storagePath, BlockLogPath: blockLogPath,
		LogLevel: logLevel, ReportIntervalSeconds: reportInterval,
	}, nil
}

func CursorStartTime(value string) (int64, error) {
	t, err := parseISOTime(value)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

func parseISOTime(value string) (time.Time, error) {
	value = strings.Replace(value, "Z", "+00:00", 1)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, value); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid ISO datetime")
}

func boolDefault(v any, d bool) (bool, error) {
	if v == nil {
		return d, nil
	}
	switch x := v.(type) {
	case bool:
		return x, nil
	case int:
		switch x {
		case 0:
			return false, nil
		case 1:
			return true, nil
		default:
			return false, fmt.Errorf("must be a boolean, got %d", x)
		}
	case string:
		switch strings.ToLower(x) {
		case "true", "yes", "on", "1":
			return true, nil
		case "false", "no", "off", "0":
			return false, nil
		}
	}
	return false, fmt.Errorf("invalid boolean")
}
func intDefault(v any, d int) (int, error) {
	if v == nil {
		return d, nil
	}
	switch x := v.(type) {
	case int:
		return x, nil
	case int64:
		return int(x), nil
	case uint64:
		if x > math.MaxInt {
			return 0, fmt.Errorf("integer overflow")
		}
		return int(x), nil
	case float64:
		return int(x), nil
	case string:
		i, e := strconv.Atoi(x)
		return i, e
	}
	return 0, fmt.Errorf("invalid integer: %v", v)
}
func floatDefault(v any, d float64) (float64, error) {
	if v == nil {
		return d, nil
	}
	switch x := v.(type) {
	case float64:
		return x, nil
	case int:
		return float64(x), nil
	case uint64:
		return float64(x), nil
	case string:
		return strconv.ParseFloat(x, 64)
	}
	return 0, fmt.Errorf("invalid number: %v", v)
}
func stringDefault(v any, d string) string {
	if v == nil {
		return d
	}
	return fmt.Sprint(v)
}
func uniqueLowerStrings(values []any) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		s := strings.ToLower(strings.TrimSpace(fmt.Sprint(v)))
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
func stringSet(values []any, lower bool) map[string]struct{} {
	r := map[string]struct{}{}
	for _, v := range values {
		s := fmt.Sprint(v)
		if lower {
			s = strings.ToLower(s)
		}
		r[s] = struct{}{}
	}
	return r
}
func compileRegexes(values []any, context string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(values))
	for _, v := range values {
		s := fmt.Sprint(v)
		if s == "" {
			return nil, fmt.Errorf("empty regex in %s", context)
		}
		r, e := regexp.Compile(s)
		if e != nil {
			return nil, fmt.Errorf("invalid regex in %s: %w", context, e)
		}
		out = append(out, r)
	}
	return out, nil
}
func parseNetworks(values []any, context string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(values))
	for _, v := range values {
		s := fmt.Sprint(v)
		var p netip.Prefix
		var e error
		if strings.Contains(s, "/") {
			p, e = netip.ParsePrefix(s)
			if e == nil {
				p = p.Masked()
			}
		} else {
			var a netip.Addr
			a, e = netip.ParseAddr(s)
			if e == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if e != nil {
			return nil, fmt.Errorf("invalid IP/CIDR in %s: %s", context, s)
		}
		out = append(out, p)
	}
	return out, nil
}
func expandedPrefix(p netip.Prefix) string {
	a := p.Addr()
	s := a.String()
	if a.Is6() {
		s = a.StringExpanded()
	}
	if p.IsSingleIP() {
		return s
	}
	return fmt.Sprintf("%s/%d", s, p.Bits())
}
func relativeTo(base, path string) (string, error) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(base, path)
	}
	return filepath.Abs(path)
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
