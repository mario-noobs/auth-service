package helpers

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/go-redis/redis/v8"
	"github.com/testcontainers/testcontainers-go"
	rediscontainer "github.com/testcontainers/testcontainers-go/modules/redis"
)

// RedisTestContainer wraps a Redis test container
type RedisTestContainer struct {
	Container *rediscontainer.RedisContainer
	Client    *redis.Client
	URL       string
}

// SetupRedisTestContainer starts a Redis container for testing
func SetupRedisTestContainer(ctx context.Context, t *testing.T) *RedisTestContainer {
	redisContainer, err := rediscontainer.RunContainer(ctx,
		testcontainers.WithImage("redis:7-alpine"),
	)
	if err != nil {
		t.Fatalf("Failed to start Redis container: %v", err)
	}

	// Get connection details
	host, err := redisContainer.Host(ctx)
	if err != nil {
		t.Fatalf("Failed to get Redis host: %v", err)
	}

	port, err := redisContainer.MappedPort(ctx, "6379")
	if err != nil {
		t.Fatalf("Failed to get Redis port: %v", err)
	}

	redisURL := fmt.Sprintf("redis://%s:%s", host, port.Port())

	// Create Redis client
	client := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%s", host, port.Port()),
	})

	// Test connection
	err = client.Ping(ctx).Err()
	if err != nil {
		t.Fatalf("Failed to connect to Redis: %v", err)
	}

	return &RedisTestContainer{
		Container: redisContainer,
		Client:    client,
		URL:       redisURL,
	}
}

// Cleanup stops the Redis container and closes connections
func (rtc *RedisTestContainer) Cleanup(ctx context.Context) error {
	if rtc.Client != nil {
		rtc.Client.Close()
	}
	if rtc.Container != nil {
		return rtc.Container.Terminate(ctx)
	}
	return nil
}

// SetRedisURL sets the REDIS_URL environment variable for the test
func (rtc *RedisTestContainer) SetRedisURL() func() {
	oldURL := os.Getenv("REDIS_URL")
	err := os.Setenv("REDIS_URL", rtc.URL)
	if err != nil {
		panic(err)
	}
	return func() {
		err := os.Setenv("REDIS_URL", oldURL)
		if err != nil {
			panic(err)
		}
	}
}
