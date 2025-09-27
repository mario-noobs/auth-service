package helpers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisTokenManager_WithTestContainer(t *testing.T) {
	ctx := context.Background()

	// Setup Redis test container
	redisTestContainer := SetupRedisTestContainer(ctx, t)
	defer func() {
		err := redisTestContainer.Cleanup(ctx)
		if err != nil {
			t.Logf("Failed to cleanup Redis container: %v", err)
		}
	}()

	// Set Redis URL for the test
	cleanup := redisTestContainer.SetRedisURL()
	defer cleanup()

	// Create a new RedisTokenManager that will use the test container
	tokenManager := NewRedisTokenManager()
	require.NotNil(t, tokenManager)

	t.Run("BlacklistToken_Success", func(t *testing.T) {
		token := "test.jwt.token"
		ttl := 5 * time.Minute

		err := tokenManager.BlacklistToken(ctx, token, ttl)
		assert.NoError(t, err)

		// Verify token is blacklisted
		isBlacklisted := tokenManager.IsTokenBlacklisted(ctx, token)
		assert.True(t, isBlacklisted)
	})

	t.Run("IsTokenBlacklisted_NotBlacklisted", func(t *testing.T) {
		token := "not.blacklisted.token"

		isBlacklisted := tokenManager.IsTokenBlacklisted(ctx, token)
		assert.False(t, isBlacklisted)
	})

	t.Run("BlacklistToken_WithBearerPrefix", func(t *testing.T) {
		token := "Bearer another.jwt.token"
		ttl := 1 * time.Minute

		err := tokenManager.BlacklistToken(ctx, token, ttl)
		assert.NoError(t, err)

		// Check with Bearer prefix
		isBlacklisted := tokenManager.IsTokenBlacklisted(ctx, token)
		assert.True(t, isBlacklisted)

		// Check without Bearer prefix
		isBlacklistedWithoutPrefix := tokenManager.IsTokenBlacklisted(ctx, "another.jwt.token")
		assert.True(t, isBlacklistedWithoutPrefix)
	})

	t.Run("TokenExpiration", func(t *testing.T) {
		token := "expiring.token"
		ttl := 100 * time.Millisecond

		err := tokenManager.BlacklistToken(ctx, token, ttl)
		assert.NoError(t, err)

		// Token should be blacklisted initially
		isBlacklisted := tokenManager.IsTokenBlacklisted(ctx, token)
		assert.True(t, isBlacklisted)

		// Wait for token to expire
		time.Sleep(150 * time.Millisecond)

		// Token should no longer be blacklisted
		isBlacklistedAfterExpiry := tokenManager.IsTokenBlacklisted(ctx, token)
		assert.False(t, isBlacklistedAfterExpiry)
	})

	t.Run("MultipleTokens", func(t *testing.T) {
		tokens := []string{"token1", "token2", "token3"}
		ttl := 2 * time.Minute

		// Blacklist multiple tokens
		for _, token := range tokens {
			err := tokenManager.BlacklistToken(ctx, token, ttl)
			assert.NoError(t, err)
		}

		// Verify all tokens are blacklisted
		for _, token := range tokens {
			isBlacklisted := tokenManager.IsTokenBlacklisted(ctx, token)
			assert.True(t, isBlacklisted, "Token %s should be blacklisted", token)
		}

		// Verify a non-blacklisted token
		isNotBlacklisted := tokenManager.IsTokenBlacklisted(ctx, "not.blacklisted")
		assert.False(t, isNotBlacklisted)
	})
}
