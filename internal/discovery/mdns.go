package discovery

import (
	"context"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var mdnsGroupAddr = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

// mdnsServices is the set of DNS-SD PTR types we query. We focus on types that
// advertise an HTTP/HTTPS interface or are otherwise interesting for a homelab.
var mdnsServices = []string{
	"_http._tcp.local.",
	"_https._tcp.local.",
	"_plex._tcp.local.",
	"_home-assistant._tcp.local.",
	"_esphomelib._tcp.local.",
	"_workstation._tcp.local.",
	"_googlecast._tcp.local.",
	"_companion-link._tcp.local.",
}

// discoverMDNS sends mDNS PTR queries for known service types and correlates
// the SRV + A records from responses into (IP, port) pairs for HTTP probing.
// Returns nil and logs a message if multicast is unavailable (common in Docker
// bridge networks — use --network=host or a macvlan network for mDNS support).
func discoverMDNS(ctx context.Context, timeout time.Duration) []openPort {
	conn, err := net.ListenMulticastUDP("udp4", nil, mdnsGroupAddr)
	if err != nil {
		log.Printf("discovery: mdns: cannot join multicast group (use --network=host for mDNS): %v", err)
		return nil
	}
	defer conn.Close()

	// Cancel the blocking read when ctx is done.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	// Send PTR queries for all known service types.
	for _, svc := range mdnsServices {
		m := new(dns.Msg)
		m.SetQuestion(svc, dns.TypePTR)
		m.RecursionDesired = false
		b, err := m.Pack()
		if err != nil {
			continue
		}
		if _, err := conn.WriteTo(b, mdnsGroupAddr); err != nil {
			break
		}
	}

	// Collect DNS records across all responses within the timeout window.
	type srvInfo struct {
		host string
		port uint16
	}
	srvMap := make(map[string]srvInfo) // instance FQDN → SRV
	aMap := make(map[string]string)    // hostname FQDN → IPv4

	buf := make([]byte, 65536)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break // deadline, closed, or ctx cancel
		}
		var msg dns.Msg
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		if !msg.Response {
			continue // skip our own outbound queries (multicast loopback)
		}
		for _, rr := range append(append(msg.Answer, msg.Ns...), msg.Extra...) {
			switch v := rr.(type) {
			case *dns.SRV:
				srvMap[strings.ToLower(v.Hdr.Name)] = srvInfo{
					host: strings.ToLower(v.Target),
					port: v.Port,
				}
			case *dns.A:
				aMap[strings.ToLower(v.Hdr.Name)] = v.A.String()
			}
		}
	}

	// Correlate SRV → hostname → IP to produce open port list.
	seen := make(map[string]bool)
	var ports []openPort
	for _, srv := range srvMap {
		ip, ok := aMap[srv.host]
		if !ok {
			// Try the system resolver (works for .local names with avahi/nss-mdns).
			host := strings.TrimSuffix(srv.host, ".")
			addrs, err := net.LookupHost(host)
			if err != nil || len(addrs) == 0 {
				continue
			}
			ip = addrs[0]
		}
		key := ip + ":" + strconv.Itoa(int(srv.port))
		if !seen[key] {
			seen[key] = true
			ports = append(ports, openPort{ip: ip, port: int(srv.port)})
		}
	}

	log.Printf("discovery: mdns: found %d services", len(ports))
	return ports
}
