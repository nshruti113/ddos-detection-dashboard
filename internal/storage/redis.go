package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/nshruti113/ddos-detection-dashboard/internal/models"
)

type RedisClient struct {
	client *redis.Client
	ctx    context.Context
}

func NewRedisClient(addr string, password string, db int) (*RedisClient, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	ctx := context.Background()

	// Test connection
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisClient{
		client: client,
		ctx:    ctx,
	}, nil
}

// StoreTraffic stores a traffic request in Redis
func (r *RedisClient) StoreTraffic(req models.TrafficRequest) error {
	// Store in a time-series sorted set
	timestamp := float64(req.Timestamp.Unix())
	key := "traffic:requests"
	
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	// Add to sorted set with timestamp as score
	if err := r.client.ZAdd(r.ctx, key, redis.Z{
		Score:  timestamp,
		Member: string(data),
	}).Err(); err != nil {
		return err
	}

	// Keep only last 5 minutes of data
	fiveMinutesAgo := float64(time.Now().Add(-5 * time.Minute).Unix())
	r.client.ZRemRangeByScore(r.ctx, key, "-inf", fmt.Sprintf("%f", fiveMinutesAgo))

	// Update real-time counters
	r.updateCounters(req)

	return nil
}

// updateCounters updates real-time metrics
func (r *RedisClient) updateCounters(req models.TrafficRequest) {
	minute := time.Now().Truncate(time.Minute).Unix()
	key := fmt.Sprintf("metrics:%d", minute)

	pipe := r.client.Pipeline()

	// Increment total requests
	pipe.HIncrBy(r.ctx, key, "total_requests", 1)

	// Increment bytes
	pipe.HIncrBy(r.ctx, key, "total_bytes", int64(req.BytesSent))

	// Add unique IP
	pipe.PFAdd(r.ctx, key+":unique_ips", req.SourceIP)

	// Increment IP counter
	pipe.ZIncrBy(r.ctx, key+":ip_counts", 1, req.SourceIP)

	// Increment path counter
	pipe.ZIncrBy(r.ctx, key+":path_counts", 1, req.RequestPath)

	// Increment protocol counter
	pipe.HIncrBy(r.ctx, key, "protocol:"+req.Protocol, 1)

	// Set expiration (keep for 1 hour)
	pipe.Expire(r.ctx, key, time.Hour)
	pipe.Expire(r.ctx, key+":unique_ips", time.Hour)
	pipe.Expire(r.ctx, key+":ip_counts", time.Hour)
	pipe.Expire(r.ctx, key+":path_counts", time.Hour)

	_, err := pipe.Exec(r.ctx)
	if err != nil {
		fmt.Printf("Error updating counters: %v\n", err)
	}
}

// GetRecentTraffic retrieves traffic from the last N seconds
func (r *RedisClient) GetRecentTraffic(seconds int) ([]models.TrafficRequest, error) {
	key := "traffic:requests"
	since := time.Now().Add(-time.Duration(seconds) * time.Second).Unix()

	results, err := r.client.ZRangeByScore(r.ctx, key, &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", since),
		Max: "+inf",
	}).Result()

	if err != nil {
		return nil, err
	}

	requests := make([]models.TrafficRequest, 0, len(results))
	for _, result := range results {
		var req models.TrafficRequest
		if err := json.Unmarshal([]byte(result), &req); err != nil {
			continue
		}
		requests = append(requests, req)
	}

	return requests, nil
}

// GetMetrics retrieves aggregated metrics for a time window
func (r *RedisClient) GetMetrics(windowStart time.Time) (*models.Metrics, error) {
	minute := windowStart.Truncate(time.Minute).Unix()
	key := fmt.Sprintf("metrics:%d", minute)

	// Get all metrics
	metricsData, err := r.client.HGetAll(r.ctx, key).Result()
	if err != nil {
		return nil, err
	}

	if len(metricsData) == 0 {
		return nil, fmt.Errorf("no metrics found for timestamp %d", minute)
	}

	// Get unique IP count
	uniqueIPs, err := r.client.PFCount(r.ctx, key+":unique_ips").Result()
	if err != nil {
		uniqueIPs = 0
	}

	// Get top IPs
	topIPsData, err := r.client.ZRevRangeWithScores(r.ctx, key+":ip_counts", 0, 9).Result()
	topIPs := make([]models.IPCount, 0, len(topIPsData))
	totalRequests := int64(0)
	
	for _, z := range topIPsData {
		count := int(z.Score)
		totalRequests += int64(count)
		topIPs = append(topIPs, models.IPCount{
			IP:    z.Member.(string),
			Count: count,
		})
	}

	// Calculate percentages
	for i := range topIPs {
		topIPs[i].Percentage = float64(topIPs[i].Count) / float64(totalRequests) * 100
	}

	// Get top paths
	topPathsData, err := r.client.ZRevRangeWithScores(r.ctx, key+":path_counts", 0, 9).Result()
	topPaths := make([]models.PathCount, 0, len(topPathsData))
	
	for _, z := range topPathsData {
		topPaths = append(topPaths, models.PathCount{
			Path:  z.Member.(string),
			Count: int(z.Score),
		})
	}

	metrics := &models.Metrics{
		Timestamp:      windowStart,
		WindowDuration: 60,
		TotalRequests:  int(totalRequests),
		UniqueIPs:      int(uniqueIPs),
		RequestsPerSec: float64(totalRequests) / 60.0,
		TopIPs:         topIPs,
		TopPaths:       topPaths,
	}

	return metrics, nil
}

// StoreAttack stores detected attack information
func (r *RedisClient) StoreAttack(attack models.Attack) error {
	data, err := json.Marshal(attack)
	if err != nil {
		return err
	}

	key := "attacks:active"
	
	// Store in hash
	if err := r.client.HSet(r.ctx, key, attack.ID, string(data)).Err(); err != nil {
		return err
	}

	// Also add to time-series
	timestamp := float64(attack.StartTime.Unix())
	if err := r.client.ZAdd(r.ctx, "attacks:history", redis.Z{
		Score:  timestamp,
		Member: attack.ID,
	}).Err(); err != nil {
		return err
	}

	return nil
}

// GetActiveAttacks retrieves currently active attacks
func (r *RedisClient) GetActiveAttacks() ([]models.Attack, error) {
	key := "attacks:active"
	
	attacksData, err := r.client.HGetAll(r.ctx, key).Result()
	if err != nil {
		return nil, err
	}

	attacks := make([]models.Attack, 0, len(attacksData))
	for _, data := range attacksData {
		var attack models.Attack
		if err := json.Unmarshal([]byte(data), &attack); err != nil {
			continue
		}
		attacks = append(attacks, attack)
	}

	return attacks, nil
}

// PublishAlert publishes an alert to subscribers
func (r *RedisClient) PublishAlert(alert models.Alert) error {
	data, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	return r.client.Publish(r.ctx, "alerts", string(data)).Err()
}

// Close closes the Redis connection
func (r *RedisClient) Close() error {
	return r.client.Close()
}