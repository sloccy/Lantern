package config

import (
	"net"
	"reflect"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		want    Config
		wantErr bool
	}{
		{
			name: "defaults",
			want: Config{
				DataDir:      "/data",
				ScanInterval: 24 * time.Hour,
				ScanTimeout:  200 * time.Millisecond,
				Compression:  true,
			},
		},
		{
			name: "all values set",
			env: map[string]string{
				"DOMAIN":          "example.com",
				"CF_API_TOKEN":    "tok",
				"CF_ZONE_ID":      "zone1",
				"CF_TUNNEL_ID":    "tun1",
				"CF_ACCOUNT_ID":   "acc1",
				"SERVER_IP":       "1.2.3.4",
				"DATA_DIR":        "/tmp/data",
				"SCAN_INTERVAL":   "1h",
				"SCAN_TIMEOUT_MS": "500",
			},
			want: Config{
				Domain:       "example.com",
				CFAPIToken:   "tok",
				CFZoneID:     "zone1",
				CFTunnelID:   "tun1",
				CFAccountID:  "acc1",
				ServerIP:     "1.2.3.4",
				DataDir:      "/tmp/data",
				ScanInterval: time.Hour,
				ScanTimeout:  500 * time.Millisecond,
				Compression:  true,
			},
		},
		{
			name: "proxy options",
			env:  map[string]string{"COMPRESSION": "false", "LOG_REQUESTS": "true"},
			want: Config{
				DataDir:      "/data",
				ScanInterval: 24 * time.Hour,
				ScanTimeout:  200 * time.Millisecond,
				LogRequests:  true,
			},
		},
		{
			name:    "invalid TRUSTED_PROXIES",
			env:     map[string]string{"TRUSTED_PROXIES": "not-an-ip"},
			wantErr: true,
		},
		{
			name:    "invalid SCAN_INTERVAL",
			env:     map[string]string{"SCAN_INTERVAL": "not-a-duration"},
			wantErr: true,
		},
		{
			name:    "invalid SCAN_TIMEOUT_MS",
			env:     map[string]string{"SCAN_TIMEOUT_MS": "abc"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear env vars that have defaults so each test is isolated.
			for _, key := range []string{
				"DOMAIN", "CF_API_TOKEN", "CF_ZONE_ID", "CF_TUNNEL_ID", "CF_ACCOUNT_ID",
				"SERVER_IP", "DATA_DIR", "SCAN_INTERVAL", "SCAN_TIMEOUT_MS",
				"COMPRESSION", "LOG_REQUESTS", "TRUSTED_PROXIES",
			} {
				t.Setenv(key, "")
			}
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			got, err := Load()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Load() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("Load() = %+v, want %+v", *got, tt.want)
			}
		})
	}
}

func TestParseTrustedProxies(t *testing.T) {
	got, err := ParseTrustedProxies("10.0.0.0/8, 192.168.1.5 ,fd00::1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d nets, want 3", len(got))
	}
	for ip, want := range map[string]bool{"10.1.2.3": true, "192.168.1.5": true, "192.168.1.6": false, "fd00::1": true, "8.8.8.8": false} {
		in := false
		for _, n := range got {
			if n.Contains(net.ParseIP(ip)) {
				in = true
			}
		}
		if in != want {
			t.Errorf("%s trusted = %v, want %v", ip, in, want)
		}
	}
}
