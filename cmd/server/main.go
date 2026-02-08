package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/nshruti113/ddos-detection-dashboard/internal/detection"
	"github.com/nshruti113/ddos-detection-dashboard/internal/models"
	"github.com/nshruti113/ddos-detection-dashboard/internal/storage"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	wsClients = make(map[*websocket.Conn]bool)
)

type Server struct {
	redis    *storage.RedisClient
	detector *detection.Detector
	router   *gin.Engine
}

func NewServer() (*Server, error) {
	// Initialize Redis
	redisClient, err := storage.NewRedisClient("localhost:6379", "", 0)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	// Initialize detector
	detector := detection.NewDetector()

	// Create Gin router
	router := gin.Default()

	server := &Server{
		redis:    redisClient,
		detector: detector,
		router:   router,
	}

	server.setupRoutes()

	return server, nil
}

func (s *Server) setupRoutes() {
	// Enable CORS
	s.router.Use(corsMiddleware())

	// API routes
	api := s.router.Group("/api")
	{
		// Traffic ingestion
		api.POST("/traffic/ingest", s.ingestTraffic)

		// Metrics
		api.GET("/metrics/current", s.getCurrentMetrics)
		api.GET("/metrics/history", s.getMetricsHistory)

		// Attacks
		api.GET("/attacks/active", s.getActiveAttacks)
		api.GET("/attacks/history", s.getAttackHistory)

		// Dashboard stats
		api.GET("/stats/summary", s.getSummaryStats)
	}

	// WebSocket endpoint
	s.router.GET("/ws", s.handleWebSocket)

	// Serve static HTML dashboard
	s.router.StaticFile("/", "./web/index.html")
}

// ingestTraffic receives and processes incoming traffic data
func (s *Server) ingestTraffic(c *gin.Context) {
	var req models.TrafficRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Store in Redis
	if err := s.redis.StoreTraffic(req); err != nil {
		log.Printf("Error storing traffic: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store traffic"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// getCurrentMetrics returns current traffic metrics
func (s *Server) getCurrentMetrics(c *gin.Context) {
	metrics, err := s.redis.GetMetrics(time.Now())
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"timestamp":      time.Now(),
			"total_requests": 0,
			"unique_ips":     0,
		})
		return
	}

	c.JSON(http.StatusOK, metrics)
}

// getMetricsHistory returns historical metrics
func (s *Server) getMetricsHistory(c *gin.Context) {
	history := make([]*models.Metrics, 0)

	for i := 0; i < 60; i++ {
		timestamp := time.Now().Add(-time.Duration(i) * time.Minute)
		metrics, err := s.redis.GetMetrics(timestamp)
		if err == nil {
			history = append(history, metrics)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"metrics": history,
	})
}

// getActiveAttacks returns currently active attacks
func (s *Server) getActiveAttacks(c *gin.Context) {
	attacks, err := s.redis.GetActiveAttacks()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"attacks": attacks,
	})
}

// getAttackHistory returns attack history
func (s *Server) getAttackHistory(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"attacks": []models.Attack{},
	})
}

// getSummaryStats returns dashboard summary statistics
func (s *Server) getSummaryStats(c *gin.Context) {
	currentMetrics, _ := s.redis.GetMetrics(time.Now())
	activeAttacks, _ := s.redis.GetActiveAttacks()

	status := "NORMAL"
	if len(activeAttacks) > 0 {
		status = "UNDER_ATTACK"
	}

	summary := gin.H{
		"status":         status,
		"active_attacks": len(activeAttacks),
		"current_rps":    0,
		"unique_ips":     0,
	}

	if currentMetrics != nil {
		summary["current_rps"] = currentMetrics.RequestsPerSec
		summary["unique_ips"] = currentMetrics.UniqueIPs
	}

	c.JSON(http.StatusOK, summary)
}

// handleWebSocket handles WebSocket connections for real-time updates
func (s *Server) handleWebSocket(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	wsClients[conn] = true
	defer delete(wsClients, conn)

	log.Println("New WebSocket client connected")

	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			log.Printf("WebSocket read error: %v", err)
			break
		}
	}
}

// broadcastMessage sends a message to all connected WebSocket clients
func broadcastMessage(message interface{}) {
	for client := range wsClients {
		err := client.WriteJSON(message)
		if err != nil {
			log.Printf("WebSocket write error: %v", err)
			client.Close()
			delete(wsClients, client)
		}
	}
}

// startAnalysisEngine runs periodic traffic analysis
func (s *Server) startAnalysisEngine() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	log.Println("🔍 Analysis engine started")

	for range ticker.C {
		// Get recent traffic
		requests, err := s.redis.GetRecentTraffic(60)
		if err != nil {
			log.Printf("Error getting recent traffic: %v", err)
			continue
		}

		if len(requests) == 0 {
			continue
		}

		// Analyze for attacks
		attacks := s.detector.AnalyzeTraffic(requests)

		// Process detected attacks
		for _, attack := range attacks {
			log.Printf("⚠️  Attack detected: %s (Confidence: %.2f)", attack.Type, attack.Confidence)

			// Store attack
			if err := s.redis.StoreAttack(attack); err != nil {
				log.Printf("Error storing attack: %v", err)
			}

			// Create alert
			alert := models.Alert{
				ID:         attack.ID,
				Level:      "CRITICAL",
				Title:      fmt.Sprintf("%s Attack Detected", attack.Type),
				Message:    attack.Description,
				AttackType: attack.Type,
				Timestamp:  time.Now(),
			}

			// Publish alert
			s.redis.PublishAlert(alert)

			// Broadcast to WebSocket clients
			broadcastMessage(map[string]interface{}{
				"type":    "alert",
				"payload": alert,
			})
		}

		// Get current metrics
		metrics, err := s.redis.GetMetrics(time.Now())
		if err == nil {
			// Broadcast metrics to WebSocket clients
			broadcastMessage(map[string]interface{}{
				"type":    "metrics",
				"payload": metrics,
			})
		}
	}
}

// corsMiddleware handles CORS
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func main() {
	log.Println("🚀 Starting DDoS Detection Dashboard Server...")

	server, err := NewServer()
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start analysis engine in background
	go server.startAnalysisEngine()

	// Start server
	log.Println("Server listening on :8888")
	if err := server.router.Run(":8888"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
