package events

type HostInfo struct {
	Hostname string `json:"hostname"`
}

type TransportEventKind struct {
	Type     string   `json:"type"`
	PID      uint32   `json:"pid,omitempty"`
	PPID     uint32   `json:"ppid,omitempty"`
	UID      uint32   `json:"uid,omitempty"`
	Comm     string   `json:"comm,omitempty"`
	Filename string   `json:"filename,omitempty"`
	Argv     []string `json:"argv,omitempty"`
	Status   string   `json:"status,omitempty"`
	DestIP   string   `json:"dest_ip,omitempty"`
	DestPort uint16   `json:"dest_port,omitempty"`
	AF       uint16   `json:"af,omitempty"`
}
