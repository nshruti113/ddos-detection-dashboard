package models

import "time"

// TrafficRequest represents a single network request
type TrafficRequest struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	SourceIP    string    `json:"source_ip"`
	DestIP      string    `json:"dest_ip"`
	SourcePort  int       `json:"source_port"`
	DestPort    int       `json:"dest_port"`
	Protocol    string    `json:"protocol"` // TCP, UDP, HTTP, etc.
	RequestPath string    `json:"request_path"`
	UserAgent   string    `json:"user_agent"`
	BytesSent   int       `json:"bytes_sent"`
	BytesRecv   int       `json:"bytes_recv"`
	StatusCode  int       `json:"status_code"`
	Duration    int       `json:"duration_ms"` // Connection duration in ms
}

// Metrics represents aggregated traffic metrics for a time window
type Metrics struct {
	Timestamp        time.Time         `json:"timestamp"`
	WindowDuration   int               `json:"window_duration_sec"`
	TotalRequests    int               `json:"total_requests"`
	UniqueIPs        int               `json:"unique_ips"`
	RequestsPerSec   float64           `json:"requests_per_sec"`
	BytesPerSec      float64           `json:"bytes_per_sec"`
	IPEntropy        float64           `json:"ip_entropy"`
	PathEntropy      float64           `json:"path_entropy"`
	TopIPs           []IPCount         `json:"top_ips"`
	TopPaths         []PathCount       `json:"top_paths"`
	ProtocolBreakdown map[string]int   `json:"protocol_breakdown"`
	StatusCodeDist   map[int]int       `json:"status_code_dist"`
	AvgConnDuration  float64           `json:"avg_connection_duration"`
}

type IPCount struct {
	IP    string  `json:"ip"`
	Count int     `json:"count"`
	Percentage float64 `json:"percentage"`
}

type PathCount struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

// Attack represents a detected attack
type Attack struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // SYN_FLOOD, HTTP_FLOOD, SLOWLORIS, UDP_FLOOD
	Severity    string    `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
	Confidence  float64   `json:"confidence"` // 0.0 to 1.0
	StartTime   time.Time `json:"start_time"`
	EndTime     *time.Time `json:"end_time,omitempty"`
	SourceIPs   []string  `json:"source_ips"`
	TargetIPs   []string  `json:"target_ips"`
	Description string    `json:"description"`
	Metrics     *Metrics  `json:"metrics,omitempty"`
	Mitigated   bool      `json:"mitigated"`
}

// MitigationAction represents a response to an attack
type MitigationAction struct {
	ID          string        `json:"id"`
	Type        string        `json:"type"` // BLOCK, RATE_LIMIT, CHALLENGE, MONITOR
	Target      string        `json:"target"` // IP or CIDR
	Duration    time.Duration `json:"duration"`
	Reason      string        `json:"reason"`
	AttackID    string        `json:"attack_id"`
	AppliedAt   time.Time     `json:"applied_at"`
	ExpiresAt   time.Time     `json:"expires_at"`
	Active      bool          `json:"active"`
}

// Alert represents a security alert
type Alert struct {
	ID          string    `json:"id"`
	Level       string    `json:"level"` // INFO, WARNING, CRITICAL
	Title       string    `json:"title"`
	Message     string    `json:"message"`
	AttackType  string    `json:"attack_type,omitempty"`
	SourceIP    string    `json:"source_ip,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	Acknowledged bool     `json:"acknowledged"`
}