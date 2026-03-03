package cf

import (
	"context"
	"fmt"

	"github.com/cloudflare/cloudflare-go"
)

// Client wraps the Cloudflare API for DNS record management.
// When created with an empty token, all methods become no-ops that return nil errors.
type Client struct {
	api    *cloudflare.API
	zoneID string
	noop   bool
}

func New(token, zoneID string) (*Client, error) {
	if token == "" || zoneID == "" {
		return &Client{noop: true}, nil
	}
	api, err := cloudflare.NewWithAPIToken(token)
	if err != nil {
		return nil, fmt.Errorf("cloudflare client: %w", err)
	}
	return &Client{api: api, zoneID: zoneID}, nil
}

// CreateRecord creates an A record and returns its ID.
func (c *Client) CreateRecord(ctx context.Context, name, ip string) (string, error) {
	if c.noop {
		return "", nil
	}
	proxied := false
	rec, err := c.api.CreateDNSRecord(ctx, cloudflare.ZoneIdentifier(c.zoneID), cloudflare.CreateDNSRecordParams{
		Type:    "A",
		Name:    name,
		Content: ip,
		TTL:     60,
		Proxied: &proxied,
	})
	if err != nil {
		return "", fmt.Errorf("create DNS record %s: %w", name, err)
	}
	return rec.ID, nil
}

// UpdateRecord updates an existing A record's content.
func (c *Client) UpdateRecord(ctx context.Context, recordID, ip string) error {
	if c.noop {
		return nil
	}
	proxied := false
	_, err := c.api.UpdateDNSRecord(ctx, cloudflare.ZoneIdentifier(c.zoneID), cloudflare.UpdateDNSRecordParams{
		ID:      recordID,
		Content: ip,
		Proxied: &proxied,
	})
	if err != nil {
		return fmt.Errorf("update DNS record %s: %w", recordID, err)
	}
	return nil
}

// DeleteRecord deletes a DNS record by ID.
func (c *Client) DeleteRecord(ctx context.Context, recordID string) error {
	if c.noop {
		return nil
	}
	return c.api.DeleteDNSRecord(ctx, cloudflare.ZoneIdentifier(c.zoneID), recordID)
}

// FindRecord looks up a record ID and current IP by exact name.
func (c *Client) FindRecord(ctx context.Context, name string) (string, string, error) {
	if c.noop {
		return "", "", nil
	}
	records, _, err := c.api.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(c.zoneID), cloudflare.ListDNSRecordsParams{
		Name: name,
	})
	if err != nil {
		return "", "", err
	}
	if len(records) == 0 {
		return "", "", nil
	}
	return records[0].ID, records[0].Content, nil
}
