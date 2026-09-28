package rules

import ("fmt"; "net"; "sync"; "time")

type NetAlert struct { Rule string; Confidence string; Reason string; Category string }

var knownC2Ports = map[uint16]string{
	4444: "Metasploit default", 4445: "Metasploit alt", 1337: "common RAT / leet port",
	31337: "Back Orifice", 6666: "common reverse shell", 6667: "IRC botnet C2",
	9001: "Tor entry / common C2", 1234: "Netcat default", 5555: "Android ADB / RAT",
	8088: "Yarn C2 / Botnet", 8888: "Empire / Covenant C2",
	8443: "alternate HTTPS C2", 10443: "common implant TLS", 47001: "WinRM alternate",
	5985: "WinRM HTTP", 5986: "WinRM HTTPS", 3389: "RDP lateral movement",
}

var suspectNetProcs = map[string]bool{
	"bash": true, "sh": true, "dash": true, "zsh": true, "fish": true, "ksh": true, "ash": true,
	"python3": true, "python": true, "perl": true, "ruby": true, "node": true, "nodejs": true,
	"php": true, "lua": true,
	"powershell": true, "powershell.exe": true, "pwsh": true, "pwsh.exe": true,
	"cmd": true, "cmd.exe": true, "wscript": true, "wscript.exe": true,
	"cscript": true, "cscript.exe": true, "mshta": true, "mshta.exe": true,
	"certutil": true, "certutil.exe": true, "rundll32": true, "rundll32.exe": true,
	"regsvr32": true, "regsvr32.exe": true, "bitsadmin": true, "bitsadmin.exe": true,
}

var browserProcs = map[string]bool{
	"firefox": true, "firefox-bin": true, "firefox.exe": true,
	"chromium": true, "chromium-browser": true, "chrome": true, "chrome.exe": true,
	"brave": true, "brave.exe": true, "msedge": true, "msedge.exe": true, "opera": true, "opera.exe": true,
}

type RateTracker struct { mu sync.Mutex; counts map[uint32][]time.Time; window time.Duration; threshold int }

func newRateTracker() *RateTracker { return &RateTracker{counts: make(map[uint32][]time.Time), window: 10 * time.Second, threshold: 20} }

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
	if label, bad := knownC2Ports[c.RemotePort]; bad {
		return &NetAlert{Rule: "NET-001", Confidence: "high", Reason: fmt.Sprintf("Process '%s' (pid %d) connected to port %d (%s). This port is associated with common C2 frameworks and reverse shells.", c.Process, c.PID, c.RemotePort, label), Category: "NET"}
	}
	if suspectNetProcs[c.Process] && c.RemotePort > 1024 {
		return &NetAlert{Rule: "NET-002", Confidence: "high", Reason: fmt.Sprintf("Process '%s' (pid %d) initiated outbound connection to %s:%d. Shells and interpreters should not make network connections.", c.Process, c.PID, c.RemoteIP.String(), c.RemotePort), Category: "NET"}
	}
	if count := e.rate.hit(c.PID); count >= e.rate.threshold {
		return &NetAlert{Rule: "NET-003", Confidence: "high", Reason: fmt.Sprintf("Process '%s' (pid %d) made %d connections in 10 seconds — matches port scan pattern.", c.Process, c.PID, count), Category: "NET"}
	}
	if c.RemotePort < 1024 && c.UID != 0 && c.RemotePort != 80 && c.RemotePort != 443 && c.RemotePort != 22 {
		return &NetAlert{Rule: "NET-004", Confidence: "medium", Reason: fmt.Sprintf("Non-root process '%s' (pid %d, uid %d) connected to privileged port %d.", c.Process, c.PID, c.UID, c.RemotePort), Category: "NET"}
	}
	if browserProcs[c.Process] && isPrivateIP(c.RemoteIP) {
		return &NetAlert{Rule: "NET-005", Confidence: "medium", Reason: fmt.Sprintf("Browser '%s' (pid %d) connected to private IP %s — possible SSRF.", c.Process, c.PID, c.RemoteIP.String()), Category: "NET"}
	}
	// NET-006: DNS to high ports or long label patterns often used in tunneling
	if c.RemotePort == 53 && suspectNetProcs[c.Process] {
		return &NetAlert{Rule: "NET-006", Confidence: "medium", Reason: fmt.Sprintf("Interpreter/shell '%s' (pid %d) speaking DNS — possible data exfil or tunnel staging.", c.Process, c.PID), Category: "NET"}
	}
	// NET-007: outbound from unexpected system paths is handled by process engine; here flag raw high-port fan-out
	if c.RemotePort >= 49152 && suspectNetProcs[c.Process] {
		return &NetAlert{Rule: "NET-007", Confidence: "low", Reason: fmt.Sprintf("Process '%s' (pid %d) connected to ephemeral port %d on %s — review for reverse shells.", c.Process, c.PID, c.RemotePort, c.RemoteIP.String()), Category: "NET"}
	}
	return nil
}

func isPrivateIP(ip net.IP) bool {
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"} {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(ip) { return true }
	}
	return false
}
