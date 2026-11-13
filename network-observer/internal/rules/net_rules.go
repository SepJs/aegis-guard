package rules

import ("fmt"; "net"; "sync"; "time")

type NetAlert struct { Rule string; Confidence string; Severity string; Reason string; Category string }

var knownC2Ports = map[uint16]string{
	4444: "Metasploit default", 4445: "Metasploit alt", 1337: "common RAT / RAT handler",
	31337: "Back Orifice", 6666: "common reverse shell", 6667: "IRC botnet C2",
	9001: "Tor / C2 relay", 5555: "Android ADB / RAT",
	8888: "Empire / Covenant C2",
}

var shellProcs = map[string]bool{
	"bash": true, "sh": true, "dash": true, "zsh": true, "fish": true, "ksh": true, "ash": true,
	"powershell": true, "powershell.exe": true, "pwsh": true, "pwsh.exe": true,
	"cmd": true, "cmd.exe": true, "wscript": true, "cscript": true, "mshta": true,
}

var browserProcs = map[string]bool{
	"firefox": true, "firefox-bin": true, "firefox.exe": true,
	"chromium": true, "chromium-browser": true, "chrome": true, "chrome.exe": true,
	"brave": true, "brave.exe": true, "msedge": true, "msedge.exe": true, "opera": true, "opera.exe": true,
}

type RateTracker struct { mu sync.Mutex; counts map[uint32][]time.Time; window time.Duration; threshold int }

func newRateTracker() *RateTracker { return &RateTracker{counts: make(map[uint32][]time.Time), window: 10 * time.Second, threshold: 60} }

func (r *RateTracker) hit(pid uint32) int {
	r.mu.Lock(); defer r.mu.Unlock()
	now := time.Now(); cutoff := now.Add(-r.window)
	var recent []time.Time
	for _, t := range r.counts[pid] { if t.After(cutoff) { recent = append(recent, t) } }
	recent = append(recent, now)
	r.counts[pid] = recent
	return len(recent)
}

type NetRuleEngine struct { rate *RateTracker }

func New() *NetRuleEngine { return &NetRuleEngine{rate: newRateTracker()} }

type ConnInfo struct { PID uint32; Process string; UID uint32; RemoteIP net.IP; RemotePort uint16; LocalPort uint16 }

func (e *NetRuleEngine) Evaluate(c *ConnInfo) *NetAlert {
	if c.RemoteIP == nil || c.RemoteIP.IsLoopback() || c.RemoteIP.IsUnspecified() {
		return nil
	}
	if label, bad := knownC2Ports[c.RemotePort]; bad {
		return &NetAlert{Rule: "NET-001", Confidence: "high", Severity: "high", Reason: fmt.Sprintf("Process '%s' (pid %d) connected to %s:%d (%s).", c.Process, c.PID, c.RemoteIP.String(), c.RemotePort, label), Category: "NET"}
	}
	if shellProcs[c.Process] && c.RemotePort > 1024 {
		return &NetAlert{Rule: "NET-002", Confidence: "high", Severity: "critical", Reason: fmt.Sprintf("Interactive shell '%s' (pid %d) initiated outbound socket to %s:%d.", c.Process, c.PID, c.RemoteIP.String(), c.RemotePort), Category: "NET"}
	}
	// Only check rate floods on non-standard web ports so normal HTTP/HTTPS bursts never trigger port-scan alerts
	if c.RemotePort != 80 && c.RemotePort != 443 && c.RemotePort != 53 {
		if count := e.rate.hit(c.PID); count >= e.rate.threshold {
			return &NetAlert{Rule: "NET-003", Confidence: "high", Severity: "high", Reason: fmt.Sprintf("Process '%s' (pid %d) opened %d non-web connections in 10 seconds — port sweep suspected.", c.Process, c.PID, count), Category: "NET"}
		}
	}
	// Browser hitting cloud instance metadata service (SSRF risk)
	if browserProcs[c.Process] && c.RemoteIP.String() == "169.254.169.254" {
		return &NetAlert{Rule: "NET-005", Confidence: "high", Severity: "high", Reason: fmt.Sprintf("Browser '%s' (pid %d) accessed cloud metadata endpoint 169.254.169.254.", c.Process, c.PID), Category: "NET"}
	}
	if c.RemotePort == 53 && shellProcs[c.Process] {
		return &NetAlert{Rule: "NET-006", Confidence: "medium", Severity: "medium", Reason: fmt.Sprintf("Shell '%s' (pid %d) communicating directly over DNS UDP/53.", c.Process, c.PID), Category: "NET"}
	}
	return nil
}
