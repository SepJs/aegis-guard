package netmon

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SepJs/aegis-guard/network-observer/internal/inspector"
	"github.com/SepJs/aegis-guard/network-observer/internal/rules"
)

const pollInterval = 500 * time.Millisecond

type Connection struct { Inode uint64; LocalIP net.IP; LocalPort uint16; RemoteIP net.IP; RemotePort uint16; Protocol string; State string; UID uint32 }
type ProcessConn struct { Connection; PID uint32; Process string }

type NetEvent struct {
	ID string; Kind string; PID uint32; Process string; Protocol string; Direction string
	LocalIP string; LocalPort uint16; RemoteIP string; RemotePort uint16
	BytesTX uint64; BytesRX uint64; Alert *rules.NetAlert; TsMs int64
}

type Monitor struct {
	rules     *rules.NetRuleEngine
	inspector *inspector.PacketInspector
	events    chan<- NetEvent
	known     map[uint64]ProcessConn
	mu        sync.Mutex
}

func New(ch chan<- NetEvent, insp *inspector.PacketInspector) *Monitor {
	return &Monitor{
		rules:     rules.New(),
		inspector: insp,
		events:    ch,
		known:     make(map[uint64]ProcessConn),
	}
}

func (m *Monitor) Run(ctx context.Context) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done(): return
		case <-ticker.C: m.poll()
		}
	}
}

func readProcNetDevTotals() (uint64, uint64) {
	f, err := os.Open("/proc/net/dev")
	if err != nil { return 0, 0 }
	defer f.Close()
	var totalRx, totalTx uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, ":")
		if idx < 0 { continue }
		fields := strings.Fields(line[idx+1:])
		if len(fields) >= 9 {
			rx, _ := strconv.ParseUint(fields[0], 10, 64)
			tx, _ := strconv.ParseUint(fields[8], 10, 64)
			totalRx += rx
			totalTx += tx
		}
	}
	return totalTx, totalRx
}

func readProcNetArp() []inspector.ArpSample {
	f, err := os.Open("/proc/net/arp")
	if err != nil { return nil }
	defer f.Close()
	var out []inspector.ArpSample
	scanner := bufio.NewScanner(f)
	scanner.Scan()
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 6 {
			out = append(out, inspector.ArpSample{IP: fields[0], Flags: fields[2], HWAddr: fields[3], Device: fields[5]})
		}
	}
	return out
}

func (m *Monitor) poll() {
	current, err := m.snapshot()
	if err != nil { return }
	txBytes, rxBytes := readProcNetDevTotals()

	if m.inspector != nil {
		flows := make([]inspector.FlowSample, 0, len(current))
		for _, conn := range current {
			flows = append(flows, inspector.FlowSample{
				Protocol:   conn.Protocol,
				LocalIP:    conn.LocalIP.String(),
				LocalPort:  conn.LocalPort,
				RemoteIP:   conn.RemoteIP.String(),
				RemotePort: conn.RemotePort,
				State:      conn.State,
				PID:        conn.PID,
				Process:    conn.Process,
				UID:        conn.UID,
				BytesTX:    txBytes,
				BytesRX:    rxBytes,
			})
		}
		findings := m.inspector.InspectSnapshot(flows, readProcNetArp())
		for _, finding := range findings {
			ev := NetEvent{
				ID:         finding.ID,
				Kind:       "packet_anomaly",
				PID:        finding.PID,
				Process:    finding.Process,
				Protocol:   strings.ToLower(finding.Protocol),
				Direction:  "outbound",
				RemoteIP:   finding.DstEndpoint,
				RemotePort: 0,
				BytesTX:    txBytes,
				BytesRX:    rxBytes,
				TsMs:       finding.TsMs,
				Alert: &rules.NetAlert{
					Rule:       finding.Rule,
					Confidence: finding.Severity,
					Severity:   finding.Severity,
					Reason:     finding.Summary,
					Category:   finding.Category,
				},
			}
			select { case m.events <- ev: default: }
		}
	}

	m.mu.Lock(); defer m.mu.Unlock()
	for inode, conn := range current {
		if _, seen := m.known[inode]; seen { continue }
		m.known[inode] = conn
		m.emit(conn, txBytes, rxBytes)
	}
	for inode := range m.known { if _, alive := current[inode]; !alive { delete(m.known, inode) } }
}

func (m *Monitor) emit(conn ProcessConn, txBytes uint64, rxBytes uint64) {
	dir := "outbound"
	if conn.LocalPort < 1024 { dir = "inbound" }
	ev := NetEvent{
		ID: fmt.Sprintf("net-%d-%d", conn.PID, time.Now().UnixNano()), Kind: "net_conn",
		PID: conn.PID, Process: conn.Process, Protocol: conn.Protocol, Direction: dir,
		LocalIP: conn.LocalIP.String(), LocalPort: conn.LocalPort,
		RemoteIP: conn.RemoteIP.String(), RemotePort: conn.RemotePort,
		BytesTX: txBytes, BytesRX: rxBytes, TsMs: time.Now().UnixMilli(),
	}
	connInfo := &rules.ConnInfo{PID: conn.PID, Process: conn.Process, UID: conn.UID, RemoteIP: conn.RemoteIP, RemotePort: conn.RemotePort, LocalPort: conn.LocalPort}
	if alert := m.rules.Evaluate(connInfo); alert != nil { ev.Kind = "net_alert"; ev.Alert = alert }
	select { case m.events <- ev: default: }
}

func (m *Monitor) snapshot() (map[uint64]ProcessConn, error) {
	if runtime.GOOS == "windows" {
		return m.snapshotWindows()
	}
	return m.snapshotLinux()
}

func (m *Monitor) snapshotLinux() (map[uint64]ProcessConn, error) {
	inodes := make(map[uint64]Connection)
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		conns, err := readProcNet(proto)
		if err != nil { continue }
		p := "tcp"
		if strings.HasPrefix(proto, "udp") { p = "udp" }
		for _, c := range conns { c.Protocol = p; inodes[c.Inode] = c }
	}
	result := make(map[uint64]ProcessConn, len(inodes))
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil { continue }
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil { continue }
		procName := readProcName(uint32(pid))
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil { continue }
			if !strings.HasPrefix(link, "socket:[") { continue }
			inodeStr := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			inode, err := strconv.ParseUint(inodeStr, 10, 64)
			if err != nil { continue }
			if conn, ok := inodes[inode]; ok { result[inode] = ProcessConn{Connection: conn, PID: uint32(pid), Process: procName} }
		}
	}
	return result, nil
}

func (m *Monitor) snapshotWindows() (map[uint64]ProcessConn, error) {
	procMap := getWindowsProcMap()
	result := make(map[uint64]ProcessConn)

	cmd := exec.Command("netstat", "-ano", "-p", "tcp")
	output, err := cmd.Output()
	if err != nil {
		return result, nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 5 || (fields[0] != "TCP" && fields[0] != "UDP") {
			continue
		}
		localIP, localPort := parseHostPort(fields[1])
		remoteIP, remotePort := parseHostPort(fields[2])
		state := fields[3]
		pidStr := fields[4]
		if len(fields) == 4 && fields[0] == "UDP" {
			pidStr = fields[3]
			state = "UDP"
		}
		pid64, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil || pid64 == 0 {
			continue
		}
		pid := uint32(pid64)
		procName := procMap[pid]
		if procName == "" {
			procName = fmt.Sprintf("pid-%d", pid)
		}

		h := uint64(localPort)<<32 | uint64(remotePort)<<16 | uint64(pid&0xFFFF)
		conn := Connection{
			Inode:      h,
			LocalIP:    localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			Protocol:   strings.ToLower(fields[0]),
			State:      state,
			UID:        1000,
		}
		result[h] = ProcessConn{
			Connection: conn,
			PID:        pid,
			Process:    procName,
		}
	}
	return result, nil
}

func parseHostPort(s string) (net.IP, uint16) {
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	idx := strings.LastIndex(s, ":")
	if idx == -1 {
		return net.IPv4(0, 0, 0, 0), 0
	}
	ipStr := s[:idx]
	portStr := s[idx+1:]
	ip := net.ParseIP(ipStr)
	if ip == nil {
		ip = net.IPv4(0, 0, 0, 0)
	}
	p, _ := strconv.ParseUint(portStr, 10, 16)
	return ip, uint16(p)
}

func getWindowsProcMap() map[uint32]string {
	res := make(map[uint32]string)
	cmd := exec.Command("tasklist", "/FO", "CSV", "/NH")
	out, err := cmd.Output()
	if err != nil {
		return res
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) >= 2 {
			name := strings.Trim(parts[0], "\" ")
			pidStr := strings.Trim(parts[1], "\" ")
			if p, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
				res[uint32(p)] = name
			}
		}
	}
	return res
}

var tcpStateMap = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
	"05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
	"09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

func readProcNet(proto string) ([]Connection, error) {
	f, err := os.Open(fmt.Sprintf("/proc/net/%s", proto))
	if err != nil { return nil, err }
	defer f.Close()
	var conns []Connection
	scanner := bufio.NewScanner(f)
	scanner.Scan()
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 { continue }
		localIP, localPort := parseAddr(fields[1])
		remoteIP, remotePort := parseAddr(fields[2])
		stateName := tcpStateMap[strings.ToUpper(fields[3])]
		if stateName == "" { stateName = "OPEN" }
		inode, _ := strconv.ParseUint(fields[9], 10, 64)
		uid32, _ := strconv.ParseUint(fields[7], 10, 32)
		conns = append(conns, Connection{Inode: inode, LocalIP: localIP, LocalPort: localPort, RemoteIP: remoteIP, RemotePort: remotePort, State: stateName, UID: uint32(uid32)})
	}
	return conns, nil
}

func parseAddr(s string) (net.IP, uint16) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 { return net.IPv4(0, 0, 0, 0), 0 }
	portVal, _ := strconv.ParseUint(parts[1], 16, 16)
	ipHex, err := hex.DecodeString(parts[0])
	if err != nil || len(ipHex) < 4 { return net.IPv4(0, 0, 0, 0), uint16(portVal) }
	ip := net.IPv4(ipHex[3], ipHex[2], ipHex[1], ipHex[0])
	return ip, uint16(portVal)
}

func readProcName(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil { return fmt.Sprintf("pid-%d", pid) }
	return strings.TrimSpace(string(data))
}
