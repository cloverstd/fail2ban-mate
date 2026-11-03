package mate

type Geo struct {
	Country   string   `json:"country,omitempty"`
	City      string   `json:"city,omitempty"`
	Latitude  *float64 `json:"latitude,omitempty"`
	Longitude *float64 `json:"longitude,omitempty"`
}
type Ban struct {
	Geo
	Jail       string `json:"jail"`
	IP         string `json:"ip"`
	ObservedAt int64  `json:"observed_at"`
}
type Event struct {
	Ban
	ID   string `json:"id"`
	Seq  int64  `json:"seq"`
	Kind string `json:"kind"`
}
type JailSnapshot struct {
	Name string `json:"name"`
	Bans []Ban  `json:"bans"`
}
type Snapshot struct {
	Seq         int64          `json:"seq"`
	Jails       []JailSnapshot `json:"jails"`
	Unavailable []string       `json:"unavailable_jails"`
}
type Command struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Jail      string `json:"jail"`
	IP        string `json:"ip"`
	ExpiresAt int64  `json:"expires_at"`
}
type Result struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}
type Policy struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	ExpiresAt *int64 `json:"expires_at"`
}
type RemoteConfig struct {
	Revision     int64  `json:"revision"`
	Mode         string `json:"mode"`
	PollInterval int    `json:"poll_interval"`
}
type ServerSync struct {
	Protocol         int          `json:"protocol"`
	Type             string       `json:"type"`
	ServerTime       int64        `json:"server_time"`
	Config           RemoteConfig `json:"config"`
	PolicyRevision   int64        `json:"policy_revision"`
	Policies         []Policy     `json:"policies"`
	Commands         []Command    `json:"commands"`
	AckEvents        []string     `json:"ack_event_ids"`
	AckResults       []string     `json:"ack_result_ids"`
	SnapshotRequired bool         `json:"snapshot_required"`
	AckSnapshotSeq   int64        `json:"ack_snapshot_seq,omitempty"`
}
type Sync struct {
	Protocol       int       `json:"protocol"`
	Type           string    `json:"type"`
	Sequence       int64     `json:"sequence"`
	Version        string    `json:"version"`
	ActualMode     string    `json:"actual_mode"`
	FallbackReason string    `json:"fallback_reason,omitempty"`
	ConfigRevision int64     `json:"applied_config_revision"`
	PolicyRevision int64     `json:"applied_policy_revision"`
	Error          string    `json:"error,omitempty"`
	Events         []Event   `json:"events"`
	Results        []Result  `json:"results"`
	Snapshot       *Snapshot `json:"snapshot,omitempty"`
}
