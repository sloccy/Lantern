package cf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
)

// TunnelEnabled reports whether Cloudflare Tunnel management is active.
func (c *Client) TunnelEnabled() bool {
	return !c.noop && c.tunnelID != "" && c.accountID != ""
}

// TunnelAvailable reports whether tunnel creation is possible (account configured),
// even if no tunnel has been created yet.
func (c *Client) TunnelAvailable() bool {
	return !c.noop && c.accountID != ""
}

// LanternOrigin is where tunnel traffic is sent: Lantern's own HTTPS listener
// (cloudflared runs in the same container). Every tunneled request therefore
// goes through Lantern's proxy exactly like a LAN request, instead of straight
// to the backend.
const LanternOrigin = "https://localhost:443"

// lanternRule is the ingress rule that sends hostname to Lantern. The original
// Host header is kept by cloudflared; the SNI is set to the hostname so
// Lantern's certificate lookup works.
func lanternRule(hostname string) ingressRule {
	return ingressRule{
		Hostname:      hostname,
		Service:       LanternOrigin,
		OriginRequest: &originRequest{NoTLSVerify: true, OriginServerName: hostname},
	}
}

// upsertRule replaces the rule for rule.Hostname in place, or appends it.
func upsertRule(rules []ingressRule, rule ingressRule) []ingressRule {
	for i := range rules {
		if rules[i].Hostname == rule.Hostname {
			rules[i] = rule
			return rules
		}
	}
	return append(rules, rule)
}

// EnsureTunnelRoutes makes sure every hostname has an ingress rule pointing at
// Lantern, rewriting stale rules (e.g. ones that point straight at a backend).
// It also prunes rules that Lantern created for hostnames under domain which no
// longer belong to a service — but only once Cloudflare confirms the hostname
// no longer has a CNAME to this tunnel. A route whose DNS still points here is
// kept even if the store does not know the service (a recreated data volume, or
// a service added while the sync was running), and a failed lookup keeps the
// rule too. Foreign rules (a different service target) and the catch-all are
// left alone. The common case (nothing to prune) costs no extra API calls.
func (c *Client) EnsureTunnelRoutes(ctx context.Context, domain string, hostnames []string) error {
	if !c.TunnelEnabled() {
		return nil
	}
	want := make(map[string]struct{}, len(hostnames))
	for _, h := range hostnames {
		want[h] = struct{}{}
	}

	var candidates []string
	if err := c.modifyIngress(ctx, func(rules []ingressRule) []ingressRule {
		for _, r := range rules {
			if domain != "" && r.Hostname != "" && r.Service == LanternOrigin &&
				strings.HasSuffix(r.Hostname, "."+domain) {
				if _, ok := want[r.Hostname]; !ok {
					candidates = append(candidates, r.Hostname)
				}
			}
		}
		for _, h := range hostnames {
			rules = upsertRule(rules, lanternRule(h))
		}
		return rules
	}); err != nil {
		return err
	}
	if len(candidates) == 0 || c.zoneID == "" {
		return nil
	}

	stale := make(map[string]struct{}, len(candidates))
	for _, h := range candidates {
		_, _, tunneled, err := c.FindTunnelCNAME(ctx, h)
		if err != nil {
			log.Printf("cf: keeping tunnel route %s: DNS check failed: %v", h, err)
			continue
		}
		if tunneled {
			continue
		}
		stale[h] = struct{}{}
	}
	if len(stale) == 0 {
		return nil
	}
	return c.modifyIngress(ctx, func(rules []ingressRule) []ingressRule {
		kept := make([]ingressRule, 0, len(rules))
		for _, r := range rules {
			if _, ok := stale[r.Hostname]; ok && r.Service == LanternOrigin {
				log.Printf("cf: pruning stale tunnel route %s", r.Hostname)
				continue
			}
			kept = append(kept, r)
		}
		return kept
	})
}

// AddTunnelRoute adds a hostname ingress rule (to Lantern) and creates the
// corresponding CNAME DNS record pointing to the tunnel endpoint.
// Any existing record at the hostname — a stale CNAME left over from a
// previous enable attempt, or an A/AAAA record that would block the CNAME —
// is overwritten in place rather than deleted. Returns the CNAME DNS record
// ID for later cleanup.
func (c *Client) AddTunnelRoute(ctx context.Context, hostname string) (cnameID string, err error) {
	if !c.TunnelEnabled() {
		return "", nil
	}
	if err := c.modifyIngress(ctx, func(rules []ingressRule) []ingressRule {
		return upsertRule(rules, lanternRule(hostname))
	}); err != nil {
		return "", fmt.Errorf("add tunnel route %s: %w", hostname, err)
	}
	cnameID, err = c.ensureTunnelCNAME(ctx, hostname)
	if err != nil {
		return "", fmt.Errorf("create CNAME for %s: %w", hostname, err)
	}
	if cnameID == "" {
		return "", fmt.Errorf("create CNAME for %s: no zone configured", hostname)
	}
	return cnameID, nil
}

// RemoveTunnelRoute deletes the hostname's CNAME DNS record and removes its
// ingress rule from the tunnel. DNS is removed first: if the ingress update
// fails or times out after the record is gone, no orphaned CNAME is left behind
// (the periodic sync prunes any leftover rule). Both steps are attempted and
// their errors combined, so one failure cannot hide the other.
func (c *Client) RemoveTunnelRoute(ctx context.Context, hostname, cnameID string) error {
	if !c.TunnelEnabled() {
		return nil
	}
	dnsErr := c.deleteTunnelCNAME(ctx, hostname, cnameID)
	ingressErr := c.modifyIngress(ctx, func(rules []ingressRule) []ingressRule {
		return removeHostname(rules, hostname)
	})
	if ingressErr != nil {
		ingressErr = fmt.Errorf("remove tunnel route %s: %w", hostname, ingressErr)
	}
	return errors.Join(dnsErr, ingressErr)
}

// deleteTunnelCNAME removes the tunnel CNAME at hostname, recovering from a lost
// or stale stored record ID. A missing record is not an error: the desired end
// state already holds. A CNAME that points anywhere other than this tunnel is
// not Lantern's, so it is logged and left alone.
func (c *Client) deleteTunnelCNAME(ctx context.Context, hostname, cnameID string) error {
	if cnameID == "" {
		id, target, ours, err := c.FindTunnelCNAME(ctx, hostname)
		if err != nil {
			return fmt.Errorf("find CNAME for %s: %w", hostname, err)
		}
		if !ours {
			if id != "" {
				log.Printf("cf: not deleting %s: CNAME points at %s, not this tunnel", hostname, target)
			}
			return nil
		}
		cnameID = id
	}
	deleteErr := c.DeleteRecord(ctx, cnameID)
	if deleteErr == nil {
		return nil
	}
	// The stored ID can be stale (the record was recreated in the dashboard,
	// or a previous attempt already removed it). If the hostname has no CNAME
	// any more, cleanup is done; if it has one of ours under a different ID,
	// remove that; a foreign CNAME is left alone.
	curID, target, ours, findErr := c.FindTunnelCNAME(ctx, hostname)
	if findErr == nil {
		if curID == "" {
			return nil
		}
		if !ours {
			log.Printf("cf: not deleting %s: CNAME points at %s, not this tunnel", hostname, target)
			return nil
		}
		if curID != cnameID {
			if err := c.DeleteRecord(ctx, curID); err == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("delete CNAME for %s: %w", hostname, deleteErr)
}

// ReplaceTunnelRoute atomically removes an old hostname route and adds a new one
// in a single ingress update, then swaps the CNAME DNS record.
// Returns the new CNAME record ID.
func (c *Client) ReplaceTunnelRoute(ctx context.Context, oldHostname, newHostname, oldCNAMEID string) (newCNAMEID string, err error) {
	if !c.TunnelEnabled() {
		return "", nil
	}
	if err := c.modifyIngress(ctx, func(rules []ingressRule) []ingressRule {
		return upsertRule(removeHostname(rules, oldHostname), lanternRule(newHostname))
	}); err != nil {
		return "", fmt.Errorf("replace tunnel route %s→%s: %w", oldHostname, newHostname, err)
	}
	newCNAMEID, err = c.ensureTunnelCNAME(ctx, newHostname)
	if err != nil {
		return "", fmt.Errorf("create CNAME for %s: %w", newHostname, err)
	}
	if oldCNAMEID != "" {
		if err := c.DeleteRecord(ctx, oldCNAMEID); err != nil {
			// Log-only: the new route is already live.
			log.Printf("cf: delete old CNAME %s: %v", oldHostname, err)
		}
	}
	return newCNAMEID, nil
}

// modifyIngress applies fn to the current tunnel ingress rules while holding
// the tunnel mutex, always ensuring the catch-all rule is last.
func (c *Client) modifyIngress(ctx context.Context, fn func([]ingressRule) []ingressRule) error {
	c.tunnelMu.Lock()
	defer c.tunnelMu.Unlock()

	result, err := c.api.do(ctx, http.MethodGet,
		"accounts/"+c.accountID+"/cfd_tunnel/"+c.tunnelID+"/configurations",
		nil,
	)
	if err != nil {
		return fmt.Errorf("get tunnel config: %w", err)
	}
	var cfg tunnelConfigResult
	if err := json.Unmarshal(result, &cfg); err != nil {
		return fmt.Errorf("decode tunnel config: %w", err)
	}

	// Separate named rules from the catch-all (Hostname == "").
	var named []ingressRule
	var catchAll *ingressRule
	for _, r := range cfg.Config.Ingress {
		if r.Hostname == "" {
			catchAll = &r
		} else {
			named = append(named, r)
		}
	}

	before := slices.Clone(named)
	named = fn(named)
	if slices.EqualFunc(before, named, ingressRuleEqual) {
		return nil // nothing to change
	}

	// Always re-append catch-all last; create a default if one wasn't present.
	if catchAll != nil {
		named = append(named, *catchAll)
	} else {
		named = append(named, ingressRule{Service: "http_status:404"})
	}

	path := "accounts/" + c.accountID + "/cfd_tunnel/" + c.tunnelID + "/configurations"
	payload := map[string]any{
		"config": map[string]any{
			"ingress": named,
		},
	}
	_, err = c.api.do(ctx, http.MethodPut, path, payload)
	if err != nil && ctx.Err() == nil {
		// PUT is idempotent; one immediate retry rides out a transient 5xx or
		// connection error when the caller's deadline still has budget left.
		_, err = c.api.do(ctx, http.MethodPut, path, payload)
	}
	if err != nil {
		return fmt.Errorf("update tunnel configuration: %w", err)
	}
	return nil
}

// createCNAME creates a proxied CNAME record pointing to the tunnel endpoint.
func (c *Client) createCNAME(ctx context.Context, hostname string) (string, error) {
	if c.noop || c.zoneID == "" {
		return "", nil
	}
	id, err := c.createDNSRecord(ctx, map[string]any{
		"type":    "CNAME",
		"name":    hostname,
		"content": c.tunnelID + ".cfargotunnel.com",
		"ttl":     1,
		"proxied": true,
	})
	if err != nil {
		return "", fmt.Errorf("create CNAME %s: %w", hostname, err)
	}
	return id, nil
}

func ingressRuleEqual(a, b ingressRule) bool {
	if a.Hostname != b.Hostname || a.Service != b.Service {
		return false
	}
	if (a.OriginRequest == nil) != (b.OriginRequest == nil) {
		return false
	}
	return a.OriginRequest == nil || *a.OriginRequest == *b.OriginRequest
}

// removeHostname returns a new slice with all rules for hostname removed.
func removeHostname(rules []ingressRule, hostname string) []ingressRule {
	filtered := make([]ingressRule, 0, len(rules))
	for _, r := range rules {
		if r.Hostname != hostname {
			filtered = append(filtered, r)
		}
	}
	return filtered
}
