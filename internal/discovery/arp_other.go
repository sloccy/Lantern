//go:build !linux

package discovery

import (
	"context"
	"time"
)

// arpSweep is not implemented on non-Linux platforms.
// Returns nil so the caller performs a full TCP sweep of all IPs.
func arpSweep(_ context.Context, _ []string, _ time.Duration) map[string]bool {
	return nil
}
