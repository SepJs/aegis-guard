// internal/rules/net_rules.go — Phase 3 network detection rules
//
// NET-001  Connection to known C2 ports                               HIGH
// NET-002  Shell/interpreter initiating outbound connection            HIGH
// NET-003  High-frequency connections (port scan pattern)             HIGH
// NET-004  Outbound to privileged port from non-root process          MEDIUM
// NET-005  Browser connecting to RFC1918 range (SSRF indicator)       MEDIUM

package rules

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// NetAlert is returned when a rule fires.
type NetAlert struct {
	Rule       string
	Confidence string
	Reason     string
	Category   string
}

// ── Static rule sets ──────────────────────────────────────────────────────────

var knownC2Ports = map[uint16]string{
	4444:  "Metasploit default",
	4445:  "Metasploit alt",
	1337:  "common RAT / leet port",
	31337: "Back Orifice",
	6666:  "common reverse shell",
	6667:  "IRC botnet C2",
	9001:  "Tor entry / common C2",
	1234:  "Netcat default",
	5555:  "Android ADB / RAT",
}

var suspectNetProcs = map[string]bool{
	"bash": true, "sh": true, "dash": true, "zsh": true,
	"fish": true, "ksh": true, "ash": true,
	"python3": true, "python": true, "perl": true,
	"ruby": true, "node": true, "nodejs": true,
	"php": true, "lua": true,
}

var browserProcs = map[string]bool{
	"firefox": true, "firefox-bin": true,
	"chromium": true, "chrome": true, "brave": true,
}

// ── Rate tracker (port scan detection) ───────────────────────────────────────

type RateTracker struct {
	mu        sync.Mutex
	counts    map[uint32][]time.Time
	window    time.Duration
	threshold int
}

func newRateTracker() *RateTracker {
	return &RateTracker{
		counts:    make(map[uint32][]time.Time),
		window:    10 * time.Second,
		threshold: 20,
	}
}

func (r *RateTracker) hit(pid uint32) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	now    := time.Now()
	cutoff := now.Add(-r.window)
	var recent []time.Time
	for _, t := range r.counts[pid] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	r.counts[pid] = recent
	return len(recent)
}

// ── NetRuleEngine ─────────────────────────────────────────────────────────────

type NetRuleEngine struct {
	rate *RateTracker
}

func New() *NetRuleEngine {
	return &NetRuleEngine{rate: newRateTracker()}
}

// ConnInfo is the minimal data each rule needs.
type ConnInfo struct {
	PID        uint32
	Process    string
	UID        uint32
	RemoteIP   net.IP
	RemotePort uint16
	LocalPort  uint16
}

func (e *NetRuleEngine) Evaluate(c *ConnInfo) *NetAlert {
	// NET-001: known C2 port
	if label, bad := knownC2Ports[c.RemotePort]; bad {
		return &NetAlert{
			Rule:       "NET-001",
			Confidence: "high",
			Reason: fmt.Sprintf(
				"Process '%s' (pid %d) connected to port %d (%s). "+
					"This port is associated with common C2 frameworks and reverse shells.",
				c.Process, c.PID, c.RemotePort, label,
			),
			Category: "NET",
		}
	}

	// NET-002: shell/interpreter outbound
	if suspectNetProcs[c.Process] && c.RemotePort > 1024 {
		return &NetAlert{
			Rule:       "NET-002",
			Confidence: "high",
			Reason: fmt.Sprintf(
				"Process '%s' (pid %d) initiated outbound connection to %s:%d. "+
					"Shells and interpreters should not make network connections — "+
					"matches reverse shell or download-and-exec pattern.",
				c.Process, c.PID, c.RemoteIP.String(), c.RemotePort,
			),
			Category: "NET",
		}
	}

	// NET-003: port scan rate
	if count := e.rate.hit(c.PID); count >= e.rate.threshold {
		return &NetAlert{
			Rule:       "NET-003",
			Confidence: "high",
			Reason: fmt.Sprintf(
				"Process '%s' (pid %d) made %d connections in 10 seconds — "+
					"matches port scan or connection flood pattern.",
				c.Process, c.PID, count,
			),
			Category: "NET",
		}
	}

	// NET-004: non-root connecting to unusual privileged port
	if c.RemotePort < 1024 && c.UID != 0 &&
		c.RemotePort != 80 && c.RemotePort != 443 && c.RemotePort != 22 {
		return &NetAlert{
			Rule:       "NET-004",
			Confidence: "medium",
			Reason: fmt.Sprintf(
				"Non-root process '%s' (pid %d, uid %d) connected to privileged port %d. "+
					"May indicate protocol tunnelling or evasion.",
				c.Process, c.PID, c.UID, c.RemotePort,
			),
			Category: "NET",
		}
	}

	// NET-005: browser → private IP (SSRF)
	if browserProcs[c.Process] && isPrivateIP(c.RemoteIP) {
		return &NetAlert{
			Rule:       "NET-005",
			Confidence: "medium",
			Reason: fmt.Sprintf(
				"Browser '%s' (pid %d) connected to private IP %s — "+
					"possible SSRF exploitation or internal network scanning.",
				c.Process, c.PID, c.RemoteIP.String(),
			),
			Category: "NET",
		}
	}

	return nil
}

func isPrivateIP(ip net.IP) bool {
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12",
		"192.168.0.0/16", "127.0.0.0/8",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
