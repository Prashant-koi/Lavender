package writer

// CanonicalRow is the format-agnostic row the store inserts. It is populated from
// the protobuf canonical event in proto.go (HandleCanonicalProto).
type CanonicalRow struct {
	EventType        string
	AgentID          string
	TenantID         string
	Hostname         string
	ObservedAtUnixMs int64
	ReceivedAtUnixMs int64
	PID              uint32
	PPID             uint32
	UID              uint32
	Comm             string
	Filename         string
	Argv             string
	DestIP           string
	DestPort         uint16
	AF               uint16
}
