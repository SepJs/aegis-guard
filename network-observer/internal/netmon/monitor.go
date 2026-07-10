package netmon

import ("bufio"; "context"; "encoding/hex"; "fmt"; "net"; "os"; "path/filepath"; "strconv"; "strings"; "sync"; "time"
	"github.com/SepJs/aegis-guard/network-observer/internal/rules")

const pollInterval = 500 * time.Millisecond

type Connection struct { Inode uint64; LocalIP net.IP; LocalPort uint16; RemoteIP net.IP; RemotePort uint16; Protocol string; State string; UID uint32 }
type ProcessConn struct { Connection; PID uint32; Process string }

type NetEvent struct {
	ID string; Kind string; PID uint32; Process string; Protocol string; Direction string
	LocalIP string; LocalPort uint16; RemoteIP string; RemotePort uint16
	BytesTX uint64; BytesRX uint64; Alert *rules.NetAlert; TsMs int64
}

type Monitor struct { rules *rules.NetRuleEngine; events chan<- NetEvent; known map[uint64]ProcessConn; mu sync.Mutex }

func New(ch chan<- NetEvent) *Monitor { return &Monitor{rules: rules.New(), events: ch, known: make(map[uint64]ProcessConn)} }

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

func (m *Monitor) poll() {
	current, err := m.snapshot()
	if err != nil { return }
	m.mu.Lock(); defer m.mu.Unlock()
	for inode, conn := range current {
		if _, seen := m.known[inode]; seen { continue }
		m.known[inode] = conn
		m.emit(conn)
	}
	for inode := range m.known { if _, alive := current[inode]; !alive { delete(m.known, inode) } }
}

func (m *Monitor) emit(conn ProcessConn) {
	dir := "outbound"
	if conn.LocalPort < 1024 { dir = "inbound" }
	ev := NetEvent{
		ID: fmt.Sprintf("net-%d-%d", conn.PID, time.Now().UnixNano()), Kind: "net_conn",
		PID: conn.PID, Process: conn.Process, Protocol: conn.Protocol, Direction: dir,
		LocalIP: conn.LocalIP.String(), LocalPort: conn.LocalPort,
		RemoteIP: conn.RemoteIP.String(), RemotePort: conn.RemotePort, TsMs: time.Now().UnixMilli(),
	}
	connInfo := &rules.ConnInfo{PID: conn.PID, Process: conn.Process, UID: conn.UID, RemoteIP: conn.RemoteIP, RemotePort: conn.RemotePort, LocalPort: conn.LocalPort}
	if alert := m.rules.Evaluate(connInfo); alert != nil { ev.Kind = "net_alert"; ev.Alert = alert }
	select { case m.events <- ev: default: }
}

func (m *Monitor) snapshot() (map[uint64]ProcessConn, error) {
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
		inode, _ := strconv.ParseUint(fields[9], 10, 64)
		uid32, _ := strconv.ParseUint(fields[7], 10, 32)
		conns = append(conns, Connection{Inode: inode, LocalIP: localIP, LocalPort: localPort, RemoteIP: remoteIP, RemotePort: remotePort, UID: uint32(uid32)})
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
