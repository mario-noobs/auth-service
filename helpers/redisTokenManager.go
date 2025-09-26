package helpers

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

// RedisTokenManager manages token blacklisting using Redis
type RedisTokenManager struct {
	client *redis.Client
}

// NewRedisTokenManager creates a new Redis token manager
func NewRedisTokenManager() *RedisTokenManager {
	redisURL := getEnvOrDefault("REDIS_URL", "redis:6379")

	// Parse Redis URL
	var addr, password string
	var db int

	if strings.HasPrefix(redisURL, "redis://") {
		// Full Redis URL format
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			log.Printf("Error parsing Redis URL, using default: %v", err)
			addr = "redis:6379"
		} else {
			addr = opt.Addr
			password = opt.Password
			db = opt.DB
		}
	} else {
		// Simple host:port format
		addr = redisURL
	}

	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		log.Printf("Warning: Redis connection failed: %v. Token blacklisting will be disabled.", err)
		return &RedisTokenManager{client: nil}
	}

	log.Printf("Redis token manager initialized successfully")
	return &RedisTokenManager{client: client}
}

// BlacklistToken adds a token to the blacklist
func (rtm *RedisTokenManager) BlacklistToken(ctx context.Context, token string, expiration time.Duration) error {
	if rtm.client == nil {
		log.Printf("Redis not available, skipping token blacklisting")
		return nil
	}

	// Remove Bearer prefix if present
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}

	key := fmt.Sprintf("blacklist:token:%s", token)

	err := rtm.client.Set(ctx, key, "blacklisted", expiration).Err()
	if err != nil {
		log.Printf("Error blacklisting token: %v", err)
		return fmt.Errorf("failed to blacklist token: %w", err)
	}

	log.Printf("Token blacklisted successfully, expires in: %v", expiration)
	return nil
}

// IsTokenBlacklisted checks if a token is blacklisted
func (rtm *RedisTokenManager) IsTokenBlacklisted(ctx context.Context, token string) bool {
	if rtm.client == nil {
		return false // If Redis is not available, assume token is not blacklisted
	}

	// Remove Bearer prefix if present
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}

	key := fmt.Sprintf("blacklist:token:%s", token)

	result := rtm.client.Get(ctx, key)
	if result.Err() == redis.Nil {
		return false // Token not found in blacklist
	}

	if result.Err() != nil {
		log.Printf("Error checking token blacklist: %v", result.Err())
		return false // On error, assume not blacklisted
	}

	log.Printf("Token found in blacklist")
	return true
}

// BlacklistUserTokens blacklists all tokens for a specific user (logout all devices)
func (rtm *RedisTokenManager) BlacklistUserTokens(ctx context.Context, userID string, expiration time.Duration) error {
	if rtm.client == nil {
		log.Printf("Redis not available, skipping user token blacklisting")
		return nil
	}

	key := fmt.Sprintf("blacklist:user:%s", userID)

	err := rtm.client.Set(ctx, key, time.Now().Unix(), expiration).Err()
	if err != nil {
		log.Printf("Error blacklisting user tokens: %v", err)
		return fmt.Errorf("failed to blacklist user tokens: %w", err)
	}

	log.Printf("All tokens for user %s blacklisted", userID)
	return nil
}

// IsUserTokensBlacklisted checks if all tokens for a user are blacklisted
func (rtm *RedisTokenManager) IsUserTokensBlacklisted(ctx context.Context, userID string, tokenIssuedAt int64) bool {
	if rtm.client == nil {
		return false
	}

	key := fmt.Sprintf("blacklist:user:%s", userID)

	result := rtm.client.Get(ctx, key)
	if result.Err() == redis.Nil {
		return false // User not found in blacklist
	}

	if result.Err() != nil {
		log.Printf("Error checking user token blacklist: %v", result.Err())
		return false
	}

	blacklistedAt, err := result.Int64()
	if err != nil {
		log.Printf("Error parsing blacklist timestamp: %v", err)
		return false
	}

	// If token was issued before user blacklist, it's blacklisted
	return tokenIssuedAt < blacklistedAt
}

// CleanupExpiredTokens removes expired tokens from blacklist (optional maintenance)
func (rtm *RedisTokenManager) CleanupExpiredTokens(ctx context.Context) error {
	if rtm.client == nil {
		return nil
	}

	// This is handled automatically by Redis TTL, but we can implement custom logic if needed
	log.Printf("Token cleanup completed (handled by Redis TTL)")
	return nil
}

// Close closes the Redis connection
func (rtm *RedisTokenManager) Close() error {
	if rtm.client != nil {
		return rtm.client.Close()
	}
	return nil
}
