package cdn

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	cdnclient "github.com/alibabacloud-go/cdn-20180510/v10/client"
	openapiutil "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	"github.com/alibabacloud-go/tea/dara"
	"github.com/aliyun/credentials-go/credentials"

	"aliyun-cdn-guard/internal/config"
	"aliyun-cdn-guard/internal/storage"
)

type Gateway interface {
	GetBlacklist(context.Context, string) (map[string]struct{}, error)
	SetBlacklist(context.Context, string, map[string]struct{}) error
}
type AliyunGateway struct {
	client          *cdnclient.Client
	ipACLXForwarded string
}

func NewAliyunGateway(cfg *config.Config, credential credentials.Credential) (*AliyunGateway, error) {
	apiCfg := new(openapiutil.Config).SetCredential(credential).SetRegionId(cfg.CDN.Region).SetEndpoint(cfg.CDN.Endpoint)
	client, err := cdnclient.NewClient(apiCfg)
	if err != nil {
		return nil, err
	}
	return &AliyunGateway{client: client, ipACLXForwarded: cfg.CDN.IPACLXForwarded}, nil
}

func (g *AliyunGateway) GetBlacklist(ctx context.Context, domain string) (map[string]struct{}, error) {
	req := new(cdnclient.DescribeCdnDomainConfigsRequest).SetDomainName(domain).SetFunctionNames("ip_black_list_set")
	resp, err := g.client.DescribeCdnDomainConfigsWithContext(ctx, req, &dara.RuntimeOptions{})
	if err != nil {
		return nil, err
	}
	out := map[string]struct{}{}
	if resp == nil || resp.Body == nil || resp.Body.DomainConfigs == nil {
		return out, nil
	}
	for _, item := range resp.Body.DomainConfigs.DomainConfig {
		if item == nil || item.FunctionName == nil || *item.FunctionName != "ip_black_list_set" || item.FunctionArgs == nil {
			continue
		}
		for _, arg := range item.FunctionArgs.FunctionArg {
			if arg != nil && arg.ArgName != nil && *arg.ArgName == "ip_list" && arg.ArgValue != nil {
				for _, v := range strings.Split(*arg.ArgValue, ",") {
					if v = strings.TrimSpace(v); v != "" {
						out[v] = struct{}{}
					}
				}
				return out, nil
			}
		}
	}
	return out, nil
}

func (g *AliyunGateway) SetBlacklist(ctx context.Context, domain string, entries map[string]struct{}) error {
	if len(entries) == 0 {
		_, err := g.client.BatchDeleteCdnDomainConfigWithContext(ctx, new(cdnclient.BatchDeleteCdnDomainConfigRequest).SetDomainNames(domain).SetFunctionNames("ip_black_list_set"), &dara.RuntimeOptions{})
		return err
	}
	values := make([]string, 0, len(entries))
	ipv4, ipv6 := 0, 0
	for entry := range entries {
		values = append(values, entry)
		if strings.Contains(entry, ":") {
			ipv6++
		} else {
			ipv4++
		}
	}
	sort.Strings(values)
	serialized := strings.Join(values, ",")
	if ipv4 > 2000 || ipv6 > 700 || len([]byte(serialized)) > 30000 {
		return fmt.Errorf("CDN blacklist limit exceeded for %s: IPv4=%d, IPv6=%d, bytes=%d", domain, ipv4, ipv6, len([]byte(serialized)))
	}
	functions, err := json.Marshal([]map[string]any{{"functionName": "ip_black_list_set", "functionArgs": []map[string]string{{"argName": "ip_list", "argValue": serialized}, {"argName": "ip_acl_xfwd", "argValue": g.ipACLXForwarded}}}})
	if err != nil {
		return err
	}
	_, err = g.client.BatchSetCdnDomainConfigWithContext(ctx, new(cdnclient.BatchSetCdnDomainConfigRequest).SetDomainNames(domain).SetFunctions(string(functions)), &dara.RuntimeOptions{})
	return err
}

type Reconciler struct {
	cfg     *config.Config
	storage *storage.Storage
	gateway Gateway
}

func NewReconciler(cfg *config.Config, s *storage.Storage, g Gateway) *Reconciler {
	return &Reconciler{cfg: cfg, storage: s, gateway: g}
}
func (r *Reconciler) Run(ctx context.Context) {
	for {
		for _, domain := range r.cfg.CDN.Domains {
			if ctx.Err() != nil {
				return
			}
			if err := r.ReconcileDomain(ctx, domain, 0); err != nil {
				slog.Error("failed to reconcile CDN blacklist", "domain", domain, "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(350 * time.Millisecond):
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(r.cfg.CDN.SyncIntervalSeconds) * time.Second):
		}
	}
}

func (r *Reconciler) ReconcileDomain(ctx context.Context, domain string, now int64) error {
	if now == 0 {
		now = time.Now().Unix()
	}
	records, err := r.storage.BlocksForDomain(ctx, domain)
	if err != nil {
		return err
	}
	permanent := setFromSlice(r.cfg.PermanentBlocklist[domain])
	if err = r.storage.SyncPermanentPolicy(ctx, domain, permanent); err != nil {
		return err
	}
	permanentState, err := r.storage.PermanentForDomain(ctx, domain)
	if err != nil {
		return err
	}
	if r.cfg.CDN.DryRun {
		desired := cloneSet(permanent)
		for _, record := range records {
			if record.BlockedUntil > now {
				desired[record.ClientIP] = struct{}{}
			}
		}
		values := keys(desired)
		slog.Info("dry-run CDN blacklist", "domain", domain, "desired_managed", values)
		return nil
	}
	current, err := r.gateway.GetBlacklist(ctx, domain)
	if err != nil {
		return err
	}
	desired := cloneSet(current)
	ownership := map[string]bool{}
	permanentOwnership := map[string]bool{}
	for _, record := range records {
		if record.BlockedUntil > now {
			if record.CDNOwned == nil {
				_, exists := current[record.ClientIP]
				ownership[record.ClientIP] = !exists
			}
			owned := record.CDNOwned != nil && *record.CDNOwned
			if owned || ownership[record.ClientIP] {
				desired[record.ClientIP] = struct{}{}
			}
		} else if record.CDNOwned != nil && *record.CDNOwned {
			delete(desired, record.ClientIP)
		}
	}
	for entry, ownedPtr := range permanentState {
		if _, configured := permanent[entry]; configured {
			if ownedPtr == nil {
				_, exists := current[entry]
				permanentOwnership[entry] = !exists
			}
			owned := ownedPtr != nil && *ownedPtr
			if owned || permanentOwnership[entry] {
				desired[entry] = struct{}{}
			}
		} else if ownedPtr != nil && *ownedPtr {
			delete(desired, entry)
		}
	}
	if !setsEqual(desired, current) {
		if err = r.gateway.SetBlacklist(ctx, domain, desired); err != nil {
			return err
		}
		slog.Info("updated CDN blacklist", "domain", domain, "entries", len(desired))
	}
	if len(ownership) > 0 {
		if err = r.storage.SetOwnership(ctx, domain, ownership); err != nil {
			return err
		}
	}
	if len(permanentOwnership) > 0 {
		if err = r.storage.SetPermanentOwnership(ctx, domain, permanentOwnership); err != nil {
			return err
		}
	}
	removed := map[string]struct{}{}
	for entry := range permanentState {
		if _, ok := permanent[entry]; !ok {
			removed[entry] = struct{}{}
		}
	}
	if len(removed) > 0 {
		return r.storage.DeletePermanentRecords(ctx, domain, removed)
	}
	return nil
}

func setFromSlice(values []string) map[string]struct{} {
	r := map[string]struct{}{}
	for _, v := range values {
		r[v] = struct{}{}
	}
	return r
}
func cloneSet(v map[string]struct{}) map[string]struct{} {
	r := map[string]struct{}{}
	for k := range v {
		r[k] = struct{}{}
	}
	return r
}
func setsEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}
func keys(v map[string]struct{}) []string {
	r := make([]string, 0, len(v))
	for k := range v {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}
