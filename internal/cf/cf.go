package cf

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
)

// Client wraps the Cloudflare API for DNS record and tunnel management.
// When created with an empty token, all methods become no-ops that return nil errors.
type Client struct {
	api       *apiClient
	zoneID    string
	accountID string
	tunnelID  string
	noop      bool
	tunnelMu  sync.Mutex // serialises get-modify-put on tunnel config
}

// New creates a Cloudflare client. All four values are optional — the client
// becomes a no-op for DNS when token/zoneID are absent, and tunnel management
// is disabled when tunnelID/accountID are absent.
func New(token, zoneID, tunnelID, accountID string) (*Client, error) {
	if token == "" || zoneID == "" {
		return &Client{noop: true}, nil
	}
	return &Client{
		api:       newAPIClient(token),
		zoneID:    zoneID,
		tunnelID:  tunnelID,
		accountID: accountID,
	}, nil
}

// ---- DNS records ------------------------------------------------------------

func (c *Client) CreateRecord(ctx context.Context, name, ip string) (string, error) {
	if c.noop {
		return "", nil
	}
	id, err := c.createDNSRecord(ctx, map[string]any{
		"type":    "A",
		"name":    name,
		"content": ip,
		"ttl":     60,
		"proxied": false,
	})
	if err != nil {
		return "", fmt.Errorf("create DNS record %s: %w", name, err)
	}
	return id, nil
}

func (c *Client) UpdateRecord(ctx context.Context, recordID, ip string) error {
	if c.noop {
		return nil
	}
	_, err := c.api.do(ctx, http.MethodPatch,
		"zones/"+c.zoneID+"/dns_records/"+recordID,
		map[string]any{"content": ip},
	)
	if err != nil {
		return fmt.Errorf("update DNS record %s: %w", recordID, err)
	}
	return nil
}

func (c *Client) DeleteRecord(ctx context.Context, recordID string) error {
	if c.noop {
		return nil
	}
	_, err := c.api.do(ctx, http.MethodDelete,
		"zones/"+c.zoneID+"/dns_records/"+recordID,
		nil,
	)
	if err != nil {
		return fmt.Errorf("delete DNS record %s: %w", recordID, err)
	}
	return nil
}

// FindRecord looks up the A record for name and returns its ID and content.
func (c *Client) FindRecord(ctx context.Context, name string) (recordID, ip string, err error) {
	return c.findRecord(ctx, name, "A")
}

func (c *Client) findRecord(ctx context.Context, name, recType string) (recordID, content string, err error) {
	if c.noop {
		return "", "", nil
	}
	path := "zones/" + c.zoneID + "/dns_records?type=" + recType + "&name=" + url.QueryEscape(name)
	result, err := c.api.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", "", fmt.Errorf("find DNS record %s: %w", name, err)
	}
	var recs []dnsRecord
	if err := json.Unmarshal(result, &recs); err != nil {
		return "", "", fmt.Errorf("decode DNS records: %w", err)
	}
	if len(recs) == 0 {
		return "", "", nil
	}
	return recs[0].ID, recs[0].Content, nil
}

// findRecords returns every DNS record for name, regardless of type.
func (c *Client) findRecords(ctx context.Context, name string) ([]dnsRecord, error) {
	if c.noop {
		return nil, nil
	}
	path := "zones/" + c.zoneID + "/dns_records?name=" + url.QueryEscape(name)
	result, err := c.api.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("find DNS records %s: %w", name, err)
	}
	var recs []dnsRecord
	if err := json.Unmarshal(result, &recs); err != nil {
		return nil, fmt.Errorf("decode DNS records: %w", err)
	}
	return recs, nil
}

// UpsertARecord makes sure an unproxied A record for name → ip exists and
// returns its ID. Creates it if missing, updates the content if changed, and
// leaves it alone if already correct. Safe to call when the record already exists.
func (c *Client) UpsertARecord(ctx context.Context, name, ip string) (string, error) {
	if c.noop {
		return "", nil
	}
	recordID, current, err := c.FindRecord(ctx, name)
	if err != nil {
		return "", err
	}
	if recordID == "" {
		return c.CreateRecord(ctx, name, ip)
	}
	if current == ip {
		return recordID, nil
	}
	if err := c.UpdateRecord(ctx, recordID, ip); err != nil {
		return "", err
	}
	return recordID, nil
}

// EnsureARecord is UpsertARecord without the record ID.
func (c *Client) EnsureARecord(ctx context.Context, name, ip string) error {
	_, err := c.UpsertARecord(ctx, name, ip)
	return err
}

// EnsureCNAME makes sure the proxied tunnel CNAME for hostname exists and
// points at the tunnel, and returns its ID.
func (c *Client) EnsureCNAME(ctx context.Context, hostname string) (string, error) {
	return c.ensureTunnelCNAME(ctx, hostname)
}

// FindTunnelCNAME reports whether hostname already has a CNAME pointing at this
// client's tunnel endpoint. It returns the record ID and target so callers can
// distinguish "no CNAME" from "CNAME to a different tunnel"; ok is true only for
// the exact <tunnelID>.cfargotunnel.com target. Records of other types are
// ignored, so an A record never counts as tunneled.
func (c *Client) FindTunnelCNAME(ctx context.Context, hostname string) (recordID, target string, ok bool, err error) {
	if c.noop || c.zoneID == "" || c.tunnelID == "" {
		return "", "", false, nil
	}
	recs, err := c.findRecords(ctx, hostname)
	if err != nil {
		return "", "", false, err
	}
	for _, r := range recs {
		if r.Type != "" && r.Type != "CNAME" {
			continue
		}
		return r.ID, r.Content, r.Content == c.tunnelID+".cfargotunnel.com", nil
	}
	return "", "", false, nil
}

// ensureTunnelCNAME makes sure the proxied tunnel CNAME for hostname exists and
// points at the tunnel, and returns its ID. No records are removed unless
// duplicated: an existing record at the hostname — including a stale A/AAAA
// record that would otherwise block CNAME creation — is rewritten in place
// (same record ID, one API call) so enabling a tunnel never deletes records.
func (c *Client) ensureTunnelCNAME(ctx context.Context, hostname string) (string, error) {
	if c.noop || c.zoneID == "" || c.tunnelID == "" {
		return "", nil
	}
	want := c.tunnelID + ".cfargotunnel.com"
	recs, err := c.findRecords(ctx, hostname)
	if err != nil {
		return "", err
	}
	if len(recs) == 0 {
		return c.createCNAME(ctx, hostname)
	}
	first := recs[0]
	// Content already correct and it is (or identifies as) a CNAME: leave it.
	if first.Content == want && (first.Type == "" || first.Type == "CNAME") {
		return first.ID, nil
	}
	if _, err := c.api.do(ctx, http.MethodPut,
		"zones/"+c.zoneID+"/dns_records/"+first.ID,
		map[string]any{
			"type":    "CNAME",
			"name":    hostname,
			"content": want,
			"ttl":     1,
			"proxied": true,
		},
	); err != nil {
		return "", fmt.Errorf("update CNAME %s: %w", hostname, err)
	}
	// Extras at the same name are defunct either way; report but don't fail.
	for _, extra := range recs[1:] {
		if err := c.DeleteRecord(ctx, extra.ID); err != nil {
			log.Printf("cf: remove duplicate record for %s: %v", hostname, err)
		}
	}
	return first.ID, nil
}

// createDNSRecord posts params to the DNS records endpoint and returns the new record ID.
func (c *Client) createDNSRecord(ctx context.Context, params map[string]any) (string, error) {
	result, err := c.api.do(ctx, http.MethodPost, "zones/"+c.zoneID+"/dns_records", params)
	if err != nil {
		return "", err
	}
	var rec dnsRecord
	if err := json.Unmarshal(result, &rec); err != nil {
		return "", fmt.Errorf("decode DNS record: %w", err)
	}
	return rec.ID, nil
}

// ---- Tunnel management ------------------------------------------------------

// CreateTunnel creates a new named Cloudflare Tunnel and returns its ID and token.
// The caller is responsible for persisting the token — it authenticates cloudflared.
func (c *Client) CreateTunnel(ctx context.Context, name string) (tunnelID, token string, err error) {
	if c.noop || c.accountID == "" {
		return "", "", errors.New("cloudflare account not configured")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", "", fmt.Errorf("generate tunnel secret: %w", err)
	}

	result, err := c.api.do(ctx, http.MethodPost,
		"accounts/"+c.accountID+"/cfd_tunnel",
		map[string]any{
			"name":          name,
			"tunnel_secret": base64.StdEncoding.EncodeToString(secret),
			"config_src":    "cloudflare",
		},
	)
	if err != nil {
		return "", "", fmt.Errorf("create tunnel: %w", err)
	}
	var tun struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(result, &tun); err != nil {
		return "", "", fmt.Errorf("decode tunnel: %w", err)
	}

	tokenResult, err := c.api.do(ctx, http.MethodGet,
		"accounts/"+c.accountID+"/cfd_tunnel/"+tun.ID+"/token",
		nil,
	)
	if err != nil {
		return "", "", fmt.Errorf("get tunnel token: %w", err)
	}
	// Result is a bare JSON string.
	var tokenStr string
	if err := json.Unmarshal(tokenResult, &tokenStr); err != nil {
		return "", "", fmt.Errorf("decode tunnel token: %w", err)
	}

	c.SetTunnelID(tun.ID)
	return tun.ID, tokenStr, nil
}

func (c *Client) DeleteTunnel(ctx context.Context, tunnelID string) error {
	if c.noop || c.accountID == "" {
		return nil
	}
	_, err := c.api.do(ctx, http.MethodDelete,
		"accounts/"+c.accountID+"/cfd_tunnel/"+tunnelID,
		nil,
	)
	if err != nil {
		return fmt.Errorf("delete tunnel %s: %w", tunnelID, err)
	}
	return nil
}

func (c *Client) SetTunnelID(id string) {
	c.tunnelMu.Lock()
	c.tunnelID = id
	c.tunnelMu.Unlock()
}
