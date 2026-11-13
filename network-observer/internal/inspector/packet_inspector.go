package inspector

import (
	"bufio"
	"fmt"
	"math"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type FlowSample struct {
	Protocol   string `json:"protocol"`
	LocalIP    string `json:"local_ip"`
	LocalPort  uint16 `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort uint16 `json:"remote_port"`
	State      string `json:"state"`
	PID        uint32 `json:"pid"`
	Process    string `json:"process"`
	UID        uint32 `json:"uid"`
	BytesTX    uint64 `json:"bytes_tx"`
	BytesRX    uint64 `json:"bytes_rx"`
}

type ArpSample struct {
	IP     string `json:"ip"`
	HWAddr string `json:"hw_addr"`
	Device string `json:"device"`
	Flags  string `json:"flags"`
}

type SnmpCounters struct {
	IPInReceives     uint64  `json:"ip_in_receives"`
	IPOutRequests    uint64  `json:"ip_out_requests"`
	IPInHdrErrors    uint64  `json:"ip_in_hdr_errors"`
	TCPActiveOpens   uint64  `json:"tcp_active_opens"`
	TCPPassiveOpens  uint64  `json:"tcp_passive_opens"`
	TCPCurrEstab     uint64  `json:"tcp_curr_estab"`
	TCPInSegs        uint64  `json:"tcp_in_segs"`
	TCPOutSegs       uint64  `json:"tcp_out_segs"`
	TCPRetransSegs   uint64  `json:"tcp_retrans_segs"`
	TCPAttemptFails  uint64  `json:"tcp_attempt_fails"`
	UDPInDatagrams   uint64  `json:"udp_in_datagrams"`
	UDPOutDatagrams  uint64  `json:"udp_out_datagrams"`
	UDPInErrors      uint64  `json:"udp_in_errors"`
	ICMPInMsgs       uint64  `json:"icmp_in_msgs"`
	ICMPOutMsgs      uint64  `json:"icmp_out_msgs"`
	SegmentsPerSec   float64 `json:"segments_per_sec"`
	RetransRatePct   float64 `json:"retrans_rate_pct"`
}

type FlowFinding struct {
	ID            string `json:"id"`
	Category      string `json:"category"`
	Severity      string `json:"severity"`
	Rule          string `json:"rule"`
	PID           uint32 `json:"pid"`
	Process       string `json:"process"`
	Protocol      string `json:"protocol"`
	SrcEndpoint   string `json:"src_endpoint"`
	DstEndpoint   string `json:"dst_endpoint"`
	State         string `json:"state"`
	Summary       string `json:"summary"`
	SignatureHit  string `json:"signature_hit"`
	ActionTaken   string `json:"action_taken"`
	TsMs          int64  `json:"ts_ms"`
}

type InspectorConfig struct {
	DeepInspection    bool `json:"deep_inspection"`
	SynFloodGuard     bool `json:"syn_flood_guard"`
	PortScanGuard     bool `json:"port_scan_guard"`
	DnsTunnelGuard    bool `json:"dns_tunnel_guard"`
	ArpSpoofGuard     bool `json:"arp_spoof_guard"`
	SynFloodThreshold int  `json:"syn_flood_threshold"`
	PortScanThreshold int  `json:"port_scan_threshold"`
}

type InspectorStats struct {
	EngineSource     string `json:"engine_source"`
	WorkerThreads    int    `json:"worker_threads"`
	PacketsInspected uint64 `json:"packets_inspected"`
	FlowsAnalyzed    uint64 `json:"flows_analyzed"`
	AnomaliesFound   uint64 `json:"anomalies_found"`
	BytesInspected   uint64 `json:"bytes_inspected"`
	ActiveSynRecv    int    `json:"active_syn_recv"`
	LastScanTsMs     int64  `json:"last_scan_ts_ms"`
}

type InspectionSnapshot struct {
	EngineSource        string          `json:"engine_source"`
	GoBridgeConnected   bool            `json:"go_bridge_connected"`
	SnmpCounters        SnmpCounters    `json:"snmp_counters"`
	Stats               InspectorStats  `json:"stats"`
	Config              InspectorConfig `json:"config"`
	FlowFindings        []FlowFinding   `json:"flow_findings"`
	ArpTable            []ArpSample     `json:"arp_table"`
}

var knownC2Ports = map[uint16]string{
	4444: "Metasploit Handler",
	4445: "Metasploit Alt Handler",
	1337: "RAT / C2 Listener",
	31337: "Back Orifice",
	6666: "Reverse Shell Channel",
	6667: "IRC Botnet C2",
	9001: "Tor / C2 Relay",
}

var interactiveShells = map[string]bool{
	"bash": true, "sh": true, "dash": true, "zsh": true, "fish": true,
	"ksh": true, "ash": true, "nc": true, "ncat": true, "netcat": true,
}

type PacketInspector struct {
	mu           sync.RWMutex
	workers      int
	config       InspectorConfig
	snmp         SnmpCounters
	lastSnmpSegs uint64
	lastSnmpTime time.Time
	findings     []FlowFinding
	arpTable     []ArpSample
	portHistory  map[uint32]map[string]time.Time

	packetsInspected atomic.Uint64
	flowsAnalyzed    atomic.Uint64
	anomaliesFound   atomic.Uint64
	bytesInspected   atomic.Uint64
	lastSynRecv      atomic.Int64
	lastScanTs       atomic.Int64
}

func New() *PacketInspector {
	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}
	return &PacketInspector{
		workers: workers,
		config: InspectorConfig{
			DeepInspection:    true,
			SynFloodGuard:     true,
			PortScanGuard:     true,
			DnsTunnelGuard:    true,
			ArpSpoofGuard:     true,
			SynFloodThreshold: 25,
			PortScanThreshold: 60,
		},
		findings:    make([]FlowFinding, 0, 128),
		portHistory: make(map[uint32]map[string]time.Time),
	}
}

func (p *PacketInspector) GetConfig() InspectorConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.config
}

func (p *PacketInspector) SetConfig(cfg InspectorConfig) InspectorConfig {
	p.mu.Lock()
	defer p.mu.Unlock()
	if cfg.SynFloodThreshold < 5 {
		cfg.SynFloodThreshold = 25
	}
	if cfg.PortScanThreshold < 15 {
		cfg.PortScanThreshold = 60
	}
	p.config = cfg
	return p.config
}

func (p *PacketInspector) InspectSnapshot(flows []FlowSample, arp []ArpSample) []FlowFinding {
	now := time.Now()
	nowMs := now.UnixMilli()
	snmp := p.readSnmpCounters(now)

	cfg := p.GetConfig()
	if !cfg.DeepInspection {
		p.mu.Lock()
		p.snmp = snmp
		p.arpTable = arp
		p.mu.Unlock()
		p.lastScanTs.Store(nowMs)
		return nil
	}

	p.flowsAnalyzed.Add(uint64(len(flows)))
	p.packetsInspected.Store(snmp.TCPInSegs + snmp.TCPOutSegs + snmp.UDPInDatagrams + snmp.UDPOutDatagrams)

	var totalBytes uint64
	var synRecvCount int
	for _, f := range flows {
		totalBytes += f.BytesTX + f.BytesRX
		if f.State == "SYN_RECV" {
			synRecvCount++
		}
	}
	p.bytesInspected.Add(totalBytes)
	p.lastSynRecv.Store(int64(synRecvCount))

	// Fan-out flows across Go worker goroutines
	jobs := make(chan FlowSample, len(flows)+1)
	out := make(chan FlowFinding, len(flows)+4)
	var wg sync.WaitGroup

	workerCount := p.workers
	if len(flows) < workerCount {
		workerCount = len(flows)
	}
	if workerCount < 1 {
		workerCount = 1
	}

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				if finding := p.inspectFlowWorker(f, cfg, nowMs); finding != nil {
					out <- *finding
				}
			}
		}()
	}

	for _, f := range flows {
		jobs <- f
	}
	close(jobs)
	wg.Wait()
	close(out)

	var freshFindings []FlowFinding
	for f := range out {
		freshFindings = append(freshFindings, f)
	}

	// SYN-Flood accumulation check
	if cfg.SynFloodGuard && synRecvCount >= cfg.SynFloodThreshold {
		freshFindings = append(freshFindings, FlowFinding{
			ID:           fmt.Sprintf("pkt-syn-%d", nowMs),
			Category:     "SYN_FLOOD_WARNING",
			Severity:     "high",
			Rule:         "PKT-SYN-001",
			PID:          0,
			Process:      "kernel-tcp-stack",
			Protocol:     "TCP",
			SrcEndpoint:  "multiple",
			DstEndpoint:  "host:syn-backlog",
			State:        "SYN_RECV",
			Summary:      fmt.Sprintf("%d concurrent half-open SYN_RECV sockets exceed threshold (%d)", synRecvCount, cfg.SynFloodThreshold),
			SignatureHit: "L4_HALF_OPEN_SYN_BACKLOG",
			ActionTaken:  "RATE_MONITORED",
			TsMs:         nowMs,
		})
	}

	// ARP Duplicate MAC check
	if cfg.ArpSpoofGuard {
		macToIPs := make(map[string][]string)
		for _, a := range arp {
			if a.HWAddr == "" || a.HWAddr == "00:00:00:00:00:00" {
				continue
			}
			macToIPs[a.HWAddr] = append(macToIPs[a.HWAddr], a.IP)
		}
		for mac, ips := range macToIPs {
			if len(ips) > 1 {
				freshFindings = append(freshFindings, FlowFinding{
					ID:           fmt.Sprintf("pkt-arp-%s-%d", mac, nowMs),
					Category:     "ARP_DUPLICATE_MAC",
					Severity:     "high",
					Rule:         "PKT-ARP-001",
					PID:          0,
					Process:      "kernel-arp",
					Protocol:     "ARP",
					SrcEndpoint:  mac,
					DstEndpoint:  strings.Join(ips, ","),
					State:        "ACTIVE",
					Summary:      fmt.Sprintf("ARP table MAC %s maps to multiple IPs: %s", mac, strings.Join(ips, ", ")),
					SignatureHit: "L2_ARP_SPOOF_COLLISION",
					ActionTaken:  "FLAGGED",
					TsMs:         nowMs,
				})
			}
		}
	}

	p.mu.Lock()
	p.snmp = snmp
	p.arpTable = arp
	if len(freshFindings) > 0 {
		p.anomaliesFound.Add(uint64(len(freshFindings)))
		p.findings = append(freshFindings, p.findings...)
		if len(p.findings) > 128 {
			p.findings = p.findings[:128]
		}
	}
	p.mu.Unlock()
	p.lastScanTs.Store(nowMs)

	return freshFindings
}

func (p *PacketInspector) inspectFlowWorker(f FlowSample, cfg InspectorConfig, nowMs int64) *FlowFinding {
	ip := net.ParseIP(f.RemoteIP)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return nil
	}

	// Known malicious C2 port outside loopback
	if label, ok := knownC2Ports[f.RemotePort]; ok && f.State == "ESTABLISHED" {
		return &FlowFinding{
			ID:           fmt.Sprintf("pkt-c2-%d-%d-%d", f.PID, f.RemotePort, nowMs),
			Category:     "C2_CHANNEL_HIT",
			Severity:     "high",
			Rule:         "PKT-C2-001",
			PID:          f.PID,
			Process:      f.Process,
			Protocol:     strings.ToUpper(f.Protocol),
			SrcEndpoint:  fmt.Sprintf("%s:%d", f.LocalIP, f.LocalPort),
			DstEndpoint:  fmt.Sprintf("%s:%d", f.RemoteIP, f.RemotePort),
			State:        f.State,
			Summary:      fmt.Sprintf("Process '%s' active connection to %s:%d (%s)", f.Process, f.RemoteIP, f.RemotePort, label),
			SignatureHit: fmt.Sprintf("PORT_SIGNATURE_%d", f.RemotePort),
			ActionTaken:  "ALERTED",
			TsMs:         nowMs,
		}
	}

	// Interactive shell directly owning non-loopback remote socket
	procLower := strings.ToLower(f.Process)
	if interactiveShells[procLower] && f.RemotePort > 1024 && f.State == "ESTABLISHED" {
		return &FlowFinding{
			ID:           fmt.Sprintf("pkt-sh-%d-%d-%d", f.PID, f.RemotePort, nowMs),
			Category:     "SHELL_RAW_SOCKET",
			Severity:     "critical",
			Rule:         "PKT-SH-001",
			PID:          f.PID,
			Process:      f.Process,
			Protocol:     strings.ToUpper(f.Protocol),
			SrcEndpoint:  fmt.Sprintf("%s:%d", f.LocalIP, f.LocalPort),
			DstEndpoint:  fmt.Sprintf("%s:%d", f.RemoteIP, f.RemotePort),
			State:        f.State,
			Summary:      fmt.Sprintf("Shell binary '%s' (pid %d) directly connected to external endpoint %s:%d", f.Process, f.PID, f.RemoteIP, f.RemotePort),
			SignatureHit: "REVERSE_SHELL_SOCKET_FD",
			ActionTaken:  "CRITICAL_FLAG",
			TsMs:         nowMs,
		}
	}

	// Sliding-window distinct target sweep detection (excludes standard web clients on 80/443)
	if cfg.PortScanGuard && f.PID > 0 && f.RemotePort != 80 && f.RemotePort != 443 && f.RemotePort != 53 {
		target := fmt.Sprintf("%s:%d", f.RemoteIP, f.RemotePort)
		now := time.Now()
		cutoff := now.Add(-15 * time.Second)

		p.mu.Lock()
		hist := p.portHistory[f.PID]
		if hist == nil {
			hist = make(map[string]time.Time)
			p.portHistory[f.PID] = hist
		}
		hist[target] = now
		for k, ts := range hist {
			if ts.Before(cutoff) {
				delete(hist, k)
			}
		}
		distinctTargets := len(hist)
		p.mu.Unlock()

		if distinctTargets >= cfg.PortScanThreshold {
			return &FlowFinding{
				ID:           fmt.Sprintf("pkt-scan-%d-%d", f.PID, nowMs),
				Category:     "PORT_SWEEP_DETECTED",
				Severity:     "high",
				Rule:         "PKT-SCAN-001",
				PID:          f.PID,
				Process:      f.Process,
				Protocol:     strings.ToUpper(f.Protocol),
				SrcEndpoint:  fmt.Sprintf("%s:%d", f.LocalIP, f.LocalPort),
				DstEndpoint:  target,
				State:        f.State,
				Summary:      fmt.Sprintf("Process '%s' probed %d distinct non-web endpoints within 15s", f.Process, distinctTargets),
				SignatureHit: "HORIZONTAL_PORT_SWEEP",
				ActionTaken:  "MONITORED",
				TsMs:         nowMs,
			}
		}
	}

	return nil
}

func (p *PacketInspector) AnalyzeDnsDomain(domain string) (bool, float64, string) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return false, 0, ""
	}
	parts := strings.Split(domain, ".")
	if len(parts) < 3 {
		return false, 0, ""
	}
	sub := parts[0]
	if len(sub) < 42 {
		return false, 0, ""
	}
	ent := shannonEntropyString(sub)
	if ent >= 3.95 {
		return true, ent, fmt.Sprintf("High-entropy DNS label len=%d entropy=%.2f", len(sub), ent)
	}
	return false, ent, ""
}

func (p *PacketInspector) Snapshot() InspectionSnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()

	findingsCopy := make([]FlowFinding, len(p.findings))
	copy(findingsCopy, p.findings)
	arpCopy := make([]ArpSample, len(p.arpTable))
	copy(arpCopy, p.arpTable)

	return InspectionSnapshot{
		EngineSource:      "GO_PACKET_INSPECTOR_V1",
		GoBridgeConnected: true,
		SnmpCounters:      p.snmp,
		Stats: InspectorStats{
			EngineSource:     "GO_PACKET_INSPECTOR_V1",
			WorkerThreads:    p.workers,
			PacketsInspected: p.packetsInspected.Load(),
			FlowsAnalyzed:    p.flowsAnalyzed.Load(),
			AnomaliesFound:   p.anomaliesFound.Load(),
			BytesInspected:   p.bytesInspected.Load(),
			ActiveSynRecv:    int(p.lastSynRecv.Load()),
			LastScanTsMs:     p.lastScanTs.Load(),
		},
		Config:       p.config,
		FlowFindings: findingsCopy,
		ArpTable:     arpCopy,
	}
}

func (p *PacketInspector) readSnmpCounters(now time.Time) SnmpCounters {
	var c SnmpCounters
	f, err := os.Open("/proc/net/snmp")
	if err != nil {
		return c
	}
	defer f.Close()

	var headers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		proto := strings.TrimSpace(line[:colon])
		fields := strings.Fields(line[colon+1:])
		if headers == nil {
			headers = fields
			continue
		}
		kv := make(map[string]uint64, len(headers))
		for i := 0; i < len(headers) && i < len(fields); i++ {
			v, _ := strconv.ParseUint(fields[i], 10, 64)
			kv[headers[i]] = v
		}
		switch proto {
		case "Ip":
			c.IPInReceives = kv["InReceives"]
			c.IPOutRequests = kv["OutRequests"]
			c.IPInHdrErrors = kv["InHdrErrors"]
		case "Tcp":
			c.TCPActiveOpens = kv["ActiveOpens"]
			c.TCPPassiveOpens = kv["PassiveOpens"]
			c.TCPCurrEstab = kv["CurrEstab"]
			c.TCPInSegs = kv["InSegs"]
			c.TCPOutSegs = kv["OutSegs"]
			c.TCPRetransSegs = kv["RetransSegs"]
			c.TCPAttemptFails = kv["AttemptFails"]
		case "Udp":
			c.UDPInDatagrams = kv["InDatagrams"]
			c.UDPOutDatagrams = kv["OutDatagrams"]
			c.UDPInErrors = kv["InErrors"]
		case "Icmp":
			c.ICMPInMsgs = kv["InMsgs"]
			c.ICMPOutMsgs = kv["OutMsgs"]
		}
		headers = nil
	}

	totalSegs := c.TCPInSegs + c.TCPOutSegs
	if !p.lastSnmpTime.IsZero() {
		dt := now.Sub(p.lastSnmpTime).Seconds()
		if dt > 0.05 && totalSegs >= p.lastSnmpSegs {
			c.SegmentsPerSec = math.Round((float64(totalSegs-p.lastSnmpSegs)/dt)*10) / 10
		}
	}
	if c.TCPOutSegs > 0 {
		c.RetransRatePct = math.Round((float64(c.TCPRetransSegs)/float64(c.TCPOutSegs))*10000) / 100
	}
	p.lastSnmpSegs = totalSegs
	p.lastSnmpTime = now
	return c
}

func shannonEntropyString(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var ent float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}
