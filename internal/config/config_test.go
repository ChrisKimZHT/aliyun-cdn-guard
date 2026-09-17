package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadLegacyFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	data := `
sls:
  endpoint: https://cn-shanghai.log.aliyuncs.com
  region: cn-shanghai
  project: project
  logstore: store
  consumer_group: aliyun-cdn-guard
  consumer_name: ""
  cursor_position: end
  fetch_interval_seconds: 2
cdn:
  region: cn-shanghai
  endpoint: cdn.aliyuncs.com
  domains: [CDN.Example.COM, cdn.example.com]
  ip_acl_xfwd: "on"
  sync_interval_seconds: 10
  dry_run: yes
detection:
  threshold: 120
  window_seconds: 60
  retention_seconds: 3600
  ua: {enabled: false}
  uri:
    enabled: true
    query_parameters:
      mode: ignore_selected
      ignored_names: [token]
penalty:
  base_duration_seconds: 600
  multiplier: 2.0
  max_duration_seconds: 86400
whitelist:
  domains: [SKIP.EXAMPLE.COM]
  ips: [127.0.0.1, 192.0.2.7/24]
  ua_regexes: ['bot']
  uri_regexes: []
permanent_blocklist:
  cdn.example.com: ['2001:db8::1']
storage: {path: data/guard.db}
logging:
  level: INFO
  report_interval_seconds: 60
  block_log_path: data/blocks.jsonl
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.CDN.Domains) != 1 || cfg.CDN.Domains[0] != "cdn.example.com" {
		t.Fatalf("domains=%v", cfg.CDN.Domains)
	}
	if !cfg.CDN.DryRun || cfg.StoragePath != filepath.Join(dir, "data", "guard.db") {
		t.Fatalf("config=%+v", cfg)
	}
	if got := cfg.PermanentBlocklist["cdn.example.com"][0]; got != "2001:0db8:0000:0000:0000:0000:0000:0001" {
		t.Fatalf("permanent=%s", got)
	}
	if _, ok := cfg.Whitelist.Domains["skip.example.com"]; !ok {
		t.Fatal("whitelist domain was not normalized")
	}
}

func TestRejectsNonBooleanInteger(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	data := `
sls: {endpoint: e, region: r, project: p, logstore: l}
cdn: {domains: [example.com], dry_run: 2}
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected invalid boolean to be rejected")
	}
}
