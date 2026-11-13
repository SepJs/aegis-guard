package grpc

import (
	"encoding/json"

	"github.com/SepJs/aegis-guard/network-observer/internal/inspector"
)

type RPCRequest struct {
	ReqID      string                     `json:"req_id,omitempty"`
	Action     string                     `json:"action"`
	IP         string                     `json:"ip,omitempty"`
	Domain     string                     `json:"domain,omitempty"`
	Config     *inspector.InspectorConfig `json:"config,omitempty"`
}

type RPCResponse struct {
	ReqID      string                       `json:"req_id,omitempty"`
	Kind       string                       `json:"kind"`
	OK         bool                         `json:"ok"`
	Error      string                       `json:"error,omitempty"`
	Snapshot   *inspector.InspectionSnapshot `json:"snapshot,omitempty"`
	Config     *inspector.InspectorConfig   `json:"config,omitempty"`
	DnsVerdict *DnsCheckResult              `json:"dns_verdict,omitempty"`
}

type DnsCheckResult struct {
	Domain     string  `json:"domain"`
	Suspicious bool    `json:"suspicious"`
	Entropy    float64 `json:"entropy"`
	Reason     string  `json:"reason,omitempty"`
}

// InspectorServer handles length-prefixed JSON IPC requests for packet inspection state.
type InspectorServer struct {
	inspector *inspector.PacketInspector
}

func NewInspectorServer(insp *inspector.PacketInspector) *InspectorServer {
	return &InspectorServer{inspector: insp}
}

func (s *InspectorServer) HandleRequest(payload []byte) ([]byte, bool) {
	var req RPCRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, false
	}

	switch req.Action {
	case "get_inspection_snapshot":
		snap := s.inspector.Snapshot()
		resp := RPCResponse{
			ReqID:    req.ReqID,
			Kind:     "rpc_response",
			OK:       true,
			Snapshot: &snap,
		}
		b, _ := json.Marshal(resp)
		return b, true

	case "set_inspector_config":
		if req.Config == nil {
			b, _ := json.Marshal(RPCResponse{ReqID: req.ReqID, Kind: "rpc_response", OK: false, Error: "missing config"})
			return b, true
		}
		updated := s.inspector.SetConfig(*req.Config)
		b, _ := json.Marshal(RPCResponse{ReqID: req.ReqID, Kind: "rpc_response", OK: true, Config: &updated})
		return b, true

	case "analyze_dns_domain":
		suspicious, ent, reason := s.inspector.AnalyzeDnsDomain(req.Domain)
		b, _ := json.Marshal(RPCResponse{
			ReqID: req.ReqID,
			Kind:  "rpc_response",
			OK:    true,
			DnsVerdict: &DnsCheckResult{
				Domain:     req.Domain,
				Suspicious: suspicious,
				Entropy:    ent,
				Reason:     reason,
			},
		})
		return b, true

	case "ping":
		b, _ := json.Marshal(RPCResponse{ReqID: req.ReqID, Kind: "rpc_response", OK: true})
		return b, true
	}

	return nil, false
}
