package detection

import (
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/nshruti113/ddos-detection-dashboard/internal/models"
)

type Detector struct {
	baseline   *Baseline
	thresholds *Thresholds
}

type Baseline struct {
	AverageRequestRate   float64
	AverageUniqueIPs     int
	AverageIPEntropy     float64
	StandardDeviation    float64
	NormalIPRatio        float64
	AvgConnectionDuration float64
}

type Thresholds struct {
	RequestsPerSecond    int
	RequestRateZScore    float64
	IPEntropyMin         float64
	ConnectionsPerIP     int
	SlowConnectionTime   int
	SYNFloodThreshold    int
	HTTPFloodThreshold   int
}

func NewDetector() *Detector {
	return &Detector{
		baseline: &Baseline{
			AverageRequestRate:    100.0,
			AverageUniqueIPs:      50,
			AverageIPEntropy:      5.5,
			StandardDeviation:     15.0,
			NormalIPRatio:         2.0,
			AvgConnectionDuration: 150.0,
		},
		thresholds: &Thresholds{
			RequestsPerSecond:  500,
			RequestRateZScore:  3.0,
			IPEntropyMin:       3.0,
			ConnectionsPerIP:   100,
			SlowConnectionTime: 30000,
			SYNFloodThreshold:  1000,
			HTTPFloodThreshold: 2000,
		},
	}
}

// AnalyzeTraffic performs comprehensive analysis on traffic data
func (d *Detector) AnalyzeTraffic(requests []models.TrafficRequest) []models.Attack {
	if len(requests) == 0 {
		return nil
	}

	attacks := make([]models.Attack, 0)

	// Calculate metrics
	metrics := d.calculateMetrics(requests)

	// Run detection algorithms
	if attack := d.detectSYNFlood(requests, metrics); attack != nil {
		attacks = append(attacks, *attack)
	}

	if attack := d.detectHTTPFlood(requests, metrics); attack != nil {
		attacks = append(attacks, *attack)
	}

	if attack := d.detectSlowloris(requests, metrics); attack != nil {
		attacks = append(attacks, *attack)
	}

	if attack := d.detectUDPFlood(requests, metrics); attack != nil {
		attacks = append(attacks, *attack)
	}

	if attack := d.detectRateAnomaly(metrics); attack != nil {
		attacks = append(attacks, *attack)
	}

	return attacks
}

// calculateMetrics computes various metrics from traffic data
func (d *Detector) calculateMetrics(requests []models.TrafficRequest) *TrafficMetrics {
	ipCounts := make(map[string]int)
	protocolCounts := make(map[string]int)
	pathCounts := make(map[string]int)
	totalDuration := 0
	synCount := 0

	for _, req := range requests {
		ipCounts[req.SourceIP]++
		protocolCounts[req.Protocol]++
		pathCounts[req.RequestPath]++
		totalDuration += req.Duration

		if req.Protocol == "TCP_SYN" {
			synCount++
		}
	}

	avgDuration := 0.0
	if len(requests) > 0 {
		avgDuration = float64(totalDuration) / float64(len(requests))
	}

	return &TrafficMetrics{
		TotalRequests:      len(requests),
		UniqueIPs:          len(ipCounts),
		IPCounts:           ipCounts,
		ProtocolCounts:     protocolCounts,
		PathCounts:         pathCounts,
		IPEntropy:          calculateEntropy(ipCounts),
		PathEntropy:        calculateEntropy(pathCounts),
		AvgConnDuration:    avgDuration,
		RequestsPerIP:      float64(len(requests)) / float64(len(ipCounts)),
		SYNPacketCount:     synCount,
	}
}

type TrafficMetrics struct {
	TotalRequests      int
	UniqueIPs          int
	IPCounts           map[string]int
	ProtocolCounts     map[string]int
	PathCounts         map[string]int
	IPEntropy          float64
	PathEntropy        float64
	AvgConnDuration    float64
	RequestsPerIP      float64
	SYNPacketCount     int
}

// detectSYNFlood detects SYN flood attacks
func (d *Detector) detectSYNFlood(requests []models.TrafficRequest, metrics *TrafficMetrics) *models.Attack {
	if metrics.SYNPacketCount < d.thresholds.SYNFloodThreshold {
		return nil
	}

	// Check if many SYN packets from few IPs
	synIPs := make(map[string]bool)
	for _, req := range requests {
		if req.Protocol == "TCP_SYN" {
			synIPs[req.SourceIP] = true
		}
	}

	// SYN flood: High SYN count, low IP diversity
	if metrics.SYNPacketCount > d.thresholds.SYNFloodThreshold && len(synIPs) < 10 {
		sourceIPs := make([]string, 0, len(synIPs))
		for ip := range synIPs {
			sourceIPs = append(sourceIPs, ip)
		}

		confidence := math.Min(float64(metrics.SYNPacketCount)/float64(d.thresholds.SYNFloodThreshold*2), 1.0)

		return &models.Attack{
			ID:          uuid.New().String(),
			Type:        "SYN_FLOOD",
			Severity:    getSeverity(confidence),
			Confidence:  confidence,
			StartTime:   time.Now(),
			SourceIPs:   sourceIPs,
			Description: fmt.Sprintf("SYN flood detected: %d SYN packets from %d IPs", metrics.SYNPacketCount, len(synIPs)),
			Mitigated:   false,
		}
	}

	return nil
}

// detectHTTPFlood detects HTTP flood attacks
func (d *Detector) detectHTTPFlood(requests []models.TrafficRequest, metrics *TrafficMetrics) *models.Attack {
	httpCount := 0
	httpIPs := make(map[string]int)

	for _, req := range requests {
		if req.Protocol == "HTTP" {
			httpCount++
			httpIPs[req.SourceIP]++
		}
	}

	// HTTP flood: High request rate, suspicious patterns
	if httpCount < d.thresholds.HTTPFloodThreshold {
		return nil
	}

	// Check for repetitive patterns (same path, low entropy)
	if metrics.PathEntropy < 2.0 {
		// Get top attacking IPs
		sourceIPs := getTopIPs(httpIPs, 20)
		
		confidence := math.Min(float64(httpCount)/float64(d.thresholds.HTTPFloodThreshold*2), 1.0)

		return &models.Attack{
			ID:          uuid.New().String(),
			Type:        "HTTP_FLOOD",
			Severity:    getSeverity(confidence),
			Confidence:  confidence,
			StartTime:   time.Now(),
			SourceIPs:   sourceIPs,
			Description: fmt.Sprintf("HTTP flood detected: %d requests with low path diversity (entropy: %.2f)", httpCount, metrics.PathEntropy),
			Mitigated:   false,
		}
	}

	return nil
}

// detectSlowloris detects Slowloris attacks
func (d *Detector) detectSlowloris(requests []models.TrafficRequest, metrics *TrafficMetrics) *models.Attack {
	slowConnections := 0
	slowIPs := make(map[string]int)

	for _, req := range requests {
		if req.Protocol == "HTTP" && req.Duration > d.thresholds.SlowConnectionTime {
			slowConnections++
			slowIPs[req.SourceIP]++
		}
	}

	// Slowloris: Many slow connections from few IPs
	if slowConnections > 100 && len(slowIPs) < 10 {
		sourceIPs := make([]string, 0, len(slowIPs))
		for ip := range slowIPs {
			sourceIPs = append(sourceIPs, ip)
		}

		confidence := math.Min(float64(slowConnections)/300.0, 1.0)

		return &models.Attack{
			ID:          uuid.New().String(),
			Type:        "SLOWLORIS",
			Severity:    getSeverity(confidence),
			Confidence:  confidence,
			StartTime:   time.Now(),
			SourceIPs:   sourceIPs,
			Description: fmt.Sprintf("Slowloris detected: %d slow connections from %d IPs", slowConnections, len(slowIPs)),
			Mitigated:   false,
		}
	}

	return nil
}

// detectUDPFlood detects UDP flood attacks
func (d *Detector) detectUDPFlood(requests []models.TrafficRequest, metrics *TrafficMetrics) *models.Attack {
	udpCount := metrics.ProtocolCounts["UDP"]
	
	if udpCount < 2000 {
		return nil
	}

	udpIPs := make(map[string]int)
	for _, req := range requests {
		if req.Protocol == "UDP" {
			udpIPs[req.SourceIP]++
		}
	}

	sourceIPs := getTopIPs(udpIPs, 20)
	confidence := math.Min(float64(udpCount)/5000.0, 1.0)

	return &models.Attack{
		ID:          uuid.New().String(),
		Type:        "UDP_FLOOD",
		Severity:    getSeverity(confidence),
		Confidence:  confidence,
		StartTime:   time.Now(),
		SourceIPs:   sourceIPs,
		Description: fmt.Sprintf("UDP flood detected: %d UDP packets from %d IPs", udpCount, len(udpIPs)),
		Mitigated:   false,
	}
}

// detectRateAnomaly detects anomalous request rates using statistical analysis
func (d *Detector) detectRateAnomaly(metrics *TrafficMetrics) *models.Attack {
	requestRate := float64(metrics.TotalRequests)
	
	// Calculate Z-score
	zScore := (requestRate - d.baseline.AverageRequestRate) / d.baseline.StandardDeviation

	if zScore > d.thresholds.RequestRateZScore {
		// Also check IP entropy
		if metrics.IPEntropy < d.thresholds.IPEntropyMin {
			sourceIPs := getTopIPs(metrics.IPCounts, 20)
			confidence := math.Min(zScore/6.0, 1.0)

			return &models.Attack{
				ID:          uuid.New().String(),
				Type:        "RATE_ANOMALY",
				Severity:    getSeverity(confidence),
				Confidence:  confidence,
				StartTime:   time.Now(),
				SourceIPs:   sourceIPs,
				Description: fmt.Sprintf("Rate anomaly detected: %.0f req/s (Z-score: %.2f), low IP entropy: %.2f", requestRate, zScore, metrics.IPEntropy),
				Mitigated:   false,
			}
		}
	}

	return nil
}

// calculateEntropy calculates Shannon entropy for a distribution
func calculateEntropy(counts map[string]int) float64 {
	total := 0
	for _, count := range counts {
		total += count
	}

	if total == 0 {
		return 0.0
	}

	entropy := 0.0
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / float64(total)
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// getTopIPs returns the top N IPs by request count
func getTopIPs(ipCounts map[string]int, n int) []string {
	type ipCount struct {
		ip    string
		count int
	}

	ips := make([]ipCount, 0, len(ipCounts))
	for ip, count := range ipCounts {
		ips = append(ips, ipCount{ip, count})
	}

	// Simple bubble sort for top N
	for i := 0; i < len(ips) && i < n; i++ {
		for j := i + 1; j < len(ips); j++ {
			if ips[j].count > ips[i].count {
				ips[i], ips[j] = ips[j], ips[i]
			}
		}
	}

	result := make([]string, 0, n)
	limit := n
	if len(ips) < n {
		limit = len(ips)
	}

	for i := 0; i < limit; i++ {
		result = append(result, ips[i].ip)
	}

	return result
}

// getSeverity determines attack severity based on confidence
func getSeverity(confidence float64) string {
	if confidence >= 0.9 {
		return "CRITICAL"
	} else if confidence >= 0.7 {
		return "HIGH"
	} else if confidence >= 0.5 {
		return "MEDIUM"
	}
	return "LOW"
}

// UpdateBaseline updates the baseline metrics from normal traffic
func (d *Detector) UpdateBaseline(metrics *TrafficMetrics) {
	// Exponential moving average
	alpha := 0.1
	
	d.baseline.AverageRequestRate = alpha*float64(metrics.TotalRequests) + (1-alpha)*d.baseline.AverageRequestRate
	d.baseline.AverageUniqueIPs = int(alpha*float64(metrics.UniqueIPs) + (1-alpha)*float64(d.baseline.AverageUniqueIPs))
	d.baseline.AverageIPEntropy = alpha*metrics.IPEntropy + (1-alpha)*d.baseline.AverageIPEntropy
	d.baseline.AvgConnectionDuration = alpha*metrics.AvgConnDuration + (1-alpha)*d.baseline.AvgConnectionDuration
}