package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/nshruti113/ddos-detection-dashboard/internal/models"
)

type Simulator struct {
	serverURL    string
	normalRate   int
	attackActive bool
	attackType   string
}

func NewSimulator(serverURL string) *Simulator {
	return &Simulator{
		serverURL:  serverURL,
		normalRate: 100,
	}
}

// GenerateNormalTraffic creates realistic user traffic
func (s *Simulator) GenerateNormalTraffic() models.TrafficRequest {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)",
	}

	paths := []string{
		"/", "/api/users", "/api/products", "/login", "/dashboard",
		"/profile", "/search", "/checkout", "/api/orders", "/help",
	}

	sourceIP := fmt.Sprintf("%d.%d.%d.%d",
		rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))

	return models.TrafficRequest{
		ID:          uuid.New().String(),
		Timestamp:   time.Now(),
		SourceIP:    sourceIP,
		DestIP:      "192.168.1.100",
		SourcePort:  rand.Intn(65535-1024) + 1024,
		DestPort:    443,
		Protocol:    "HTTP",
		RequestPath: paths[rand.Intn(len(paths))],
		UserAgent:   userAgents[rand.Intn(len(userAgents))],
		BytesSent:   rand.Intn(1000) + 100,
		BytesRecv:   rand.Intn(5000) + 200,
		StatusCode:  200,
		Duration:    rand.Intn(200) + 50,
	}
}

// GenerateSYNFlood simulates SYN flood attack
func (s *Simulator) GenerateSYNFlood() []models.TrafficRequest {
	requests := make([]models.TrafficRequest, 0)

	attackIPs := []string{
		"203.0.113.10", "203.0.113.11", "203.0.113.12",
	}

	count := rand.Intn(4000) + 1000

	for i := 0; i < count; i++ {
		req := models.TrafficRequest{
			ID:         uuid.New().String(),
			Timestamp:  time.Now(),
			SourceIP:   attackIPs[rand.Intn(len(attackIPs))],
			DestIP:     "192.168.1.100",
			SourcePort: rand.Intn(65535),
			DestPort:   80,
			Protocol:   "TCP_SYN",
			BytesSent:  64,
			Duration:   0,
		}
		requests = append(requests, req)
	}

	return requests
}

// GenerateHTTPFlood simulates HTTP flood attack
func (s *Simulator) GenerateHTTPFlood() []models.TrafficRequest {
	requests := make([]models.TrafficRequest, 0)

	attackIPs := generateBotnet(50)
	targetPaths := []string{"/api/search", "/login"}

	count := rand.Intn(3000) + 2000

	for i := 0; i < count; i++ {
		req := models.TrafficRequest{
			ID:          uuid.New().String(),
			Timestamp:   time.Now(),
			SourceIP:    attackIPs[rand.Intn(len(attackIPs))],
			DestIP:      "192.168.1.100",
			SourcePort:  rand.Intn(65535-1024) + 1024,
			DestPort:    443,
			Protocol:    "HTTP",
			RequestPath: targetPaths[rand.Intn(len(targetPaths))],
			UserAgent:   "curl/7.68.0",
			BytesSent:   rand.Intn(500) + 100,
			BytesRecv:   rand.Intn(1000) + 200,
			StatusCode:  200,
			Duration:    rand.Intn(100) + 20,
		}
		requests = append(requests, req)
	}

	return requests
}

// GenerateSlowloris simulates Slowloris attack
func (s *Simulator) GenerateSlowloris() []models.TrafficRequest {
	requests := make([]models.TrafficRequest, 0)

	attackIPs := []string{
		"198.51.100.20", "198.51.100.21", "198.51.100.22",
	}

	count := rand.Intn(500) + 200

	for i := 0; i < count; i++ {
		req := models.TrafficRequest{
			ID:         uuid.New().String(),
			Timestamp:  time.Now(),
			SourceIP:   attackIPs[rand.Intn(len(attackIPs))],
			DestIP:     "192.168.1.100",
			SourcePort: rand.Intn(65535-1024) + 1024,
			DestPort:   80,
			Protocol:   "HTTP",
			BytesSent:  10,
			Duration:   rand.Intn(30000) + 60000,
		}
		requests = append(requests, req)
	}

	return requests
}

// GenerateUDPFlood simulates UDP flood attack
func (s *Simulator) GenerateUDPFlood() []models.TrafficRequest {
	requests := make([]models.TrafficRequest, 0)

	attackIPs := generateBotnet(30)

	count := rand.Intn(5000) + 3000

	for i := 0; i < count; i++ {
		req := models.TrafficRequest{
			ID:         uuid.New().String(),
			Timestamp:  time.Now(),
			SourceIP:   attackIPs[rand.Intn(len(attackIPs))],
			DestIP:     "192.168.1.100",
			SourcePort: rand.Intn(65535),
			DestPort:   rand.Intn(65535),
			Protocol:   "UDP",
			BytesSent:  rand.Intn(1400) + 100,
			Duration:   0,
		}
		requests = append(requests, req)
	}

	return requests
}

// Helper function to generate botnet IPs
func generateBotnet(size int) []string {
	ips := make([]string, size)
	for i := 0; i < size; i++ {
		ips[i] = fmt.Sprintf("%d.%d.%d.%d",
			rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
	}
	return ips
}

// SendTraffic sends generated traffic to the server
func (s *Simulator) SendTraffic(req models.TrafficRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := http.Post(s.serverURL+"/api/traffic/ingest", "application/json",
		bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// Run starts the simulator
func (s *Simulator) Run() {
	fmt.Println("🚀 Starting Traffic Simulator...")
	fmt.Println("Generating normal traffic at", s.normalRate, "req/sec")
	fmt.Println("🎯 DEMO MODE: Will cycle through all attack types")

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	attackTicker := time.NewTicker(10 * time.Second) // Attack every 10 seconds
	defer attackTicker.Stop()

	// Attack sequence for demo
	attackSequence := []string{"HTTP_FLOOD", "SYN_FLOOD", "SLOWLORIS", "UDP_FLOOD"}
	currentAttackIndex := 0

	// Start first attack immediately
	s.attackActive = true
	s.attackType = attackSequence[0]
	fmt.Printf("⚠️  Starting %s attack\n", s.attackType)

	for {
		select {
		case <-ticker.C:
			// Generate normal traffic
			for i := 0; i < s.normalRate; i++ {
				req := s.GenerateNormalTraffic()
				go s.SendTraffic(req)
			}

			// Generate attack traffic if active
			if s.attackActive {
				var attackRequests []models.TrafficRequest

				switch s.attackType {
				case "SYN_FLOOD":
					attackRequests = s.GenerateSYNFlood()
				case "HTTP_FLOOD":
					attackRequests = s.GenerateHTTPFlood()
				case "SLOWLORIS":
					attackRequests = s.GenerateSlowloris()
				case "UDP_FLOOD":
					attackRequests = s.GenerateUDPFlood()
				}

				for _, req := range attackRequests {
					go s.SendTraffic(req)
				}
			}

		case <-attackTicker.C:
			// Cycle to next attack type
			if s.attackActive {
				fmt.Println("✅ Attack stopped")
				s.attackActive = false
			} else {
				currentAttackIndex = (currentAttackIndex + 1) % len(attackSequence)
				s.attackActive = true
				s.attackType = attackSequence[currentAttackIndex]
				fmt.Printf("⚠️  Starting %s attack\n", s.attackType)
			}
		}
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())

	serverURL := "http://localhost:8888"
	simulator := NewSimulator(serverURL)

	fmt.Println("DDoS Detection - Traffic Simulator")
	fmt.Println("===================================")

	simulator.Run()
}
