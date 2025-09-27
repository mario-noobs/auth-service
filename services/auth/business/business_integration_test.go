package business

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"demo-service/helpers"
	"demo-service/proto/pb"
	"demo-service/services/auth/entity"
)

// Integration tests using Redis test container
func TestBusiness_IntegrationWithRedis(t *testing.T) {
	ctx := context.Background()

	// Setup Redis test container
	redisTestContainer := helpers.SetupRedisTestContainer(ctx, t)
	defer func() {
		err := redisTestContainer.Cleanup(ctx)
		if err != nil {
			t.Logf("Failed to cleanup Redis container: %v", err)
		}
	}()

	// Set Redis URL for the test
	cleanup := redisTestContainer.SetRedisURL()
	defer cleanup()

	t.Run("Login_Logout_Integration", func(t *testing.T) {
		biz := createTestBusiness(
			&mockAuthRepo{
				GetAuthFunc: func(ctx context.Context, email string) (*entity.Auth, error) {
					return &entity.Auth{UserId: 1, Password: "hashed", Salt: "salt"}, nil
				},
			},
			&mockUserRepo{},
			&mockJWTProvider{
				IssueTokenFunc: func(ctx context.Context, id, sub string) (string, int, error) {
					return "access.token.jwt", 3600, nil
				},
				IssueRefreshTokenFunc: func(ctx context.Context, id, sub string) (string, int, error) {
					return "refresh.token.jwt", 7200, nil
				},
				ParseTokenFunc: func(ctx context.Context, token string) (*jwt.RegisteredClaims, error) {
					return &jwt.RegisteredClaims{
						ID:        "token123",
						Subject:   "user456",
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					}, nil
				},
			},
			&mockHasher{
				CompareHashPasswordFunc: func(hashed, salt, password string) bool { return true },
			},
		)

		// Login should succeed
		loginResp, err := biz.Login(ctx, &pb.AuthEmailPassword{
			Email:    "test@example.com",
			Password: "password123",
		})
		require.NoError(t, err)
		require.NotNil(t, loginResp)
		assert.Equal(t, "access.token.jwt", loginResp.AccessToken.Token)

		// Token should not be blacklisted initially
		claims, err := biz.IntrospectToken(ctx, "access.token.jwt")
		require.NoError(t, err)
		assert.Equal(t, "token123", claims.ID)

		// Logout should blacklist the token
		_, err = biz.Logout(ctx, "access.token.jwt")
		require.NoError(t, err)

		// Token should now be blacklisted
		_, err = biz.IntrospectToken(ctx, "access.token.jwt")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been revoked")
	})

	t.Run("RefreshToken_Integration", func(t *testing.T) {
		biz := createTestBusiness(
			&mockAuthRepo{},
			&mockUserRepo{},
			&mockJWTProvider{
				IssueTokenFunc: func(ctx context.Context, id, sub string) (string, int, error) {
					return "new.access.token", 3600, nil
				},
				IssueRefreshTokenFunc: func(ctx context.Context, id, sub string) (string, int, error) {
					return "new.refresh.token", 7200, nil
				},
				ParseTokenFunc: func(ctx context.Context, token string) (*jwt.RegisteredClaims, error) {
					if token == "valid.refresh.token" {
						return &jwt.RegisteredClaims{
							ID:        "refresh123",
							Subject:   "user456",
							ExpiresAt: jwt.NewNumericDate(time.Now().Add(2 * time.Hour)),
						}, nil
					}
					return nil, jwt.ErrTokenMalformed
				},
			},
			&mockHasher{},
		)

		// Refresh token should succeed
		refreshResp, err := biz.RefreshToken(ctx, "valid.refresh.token")
		require.NoError(t, err)
		require.NotNil(t, refreshResp)
		assert.Equal(t, "new.access.token", refreshResp.AccessToken.Token)
		assert.Equal(t, "new.refresh.token", refreshResp.RefreshToken.Token)

		// Old refresh token should be blacklisted now
		_, err = biz.RefreshToken(ctx, "valid.refresh.token")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "refresh token has been revoked")
	})

	t.Run("TokenBlacklist_PersistenceTest", func(t *testing.T) {
		// Create first business instance
		biz1 := createTestBusiness(
			&mockAuthRepo{},
			&mockUserRepo{},
			&mockJWTProvider{
				ParseTokenFunc: func(ctx context.Context, token string) (*jwt.RegisteredClaims, error) {
					return &jwt.RegisteredClaims{
						ID:        "shared123",
						Subject:   "user789",
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					}, nil
				},
			},
			&mockHasher{},
		)

		// Blacklist token with first instance
		_, err := biz1.Logout(ctx, "shared.token")
		require.NoError(t, err)

		// Create second business instance (simulating different service instance)
		biz2 := createTestBusiness(
			&mockAuthRepo{},
			&mockUserRepo{},
			&mockJWTProvider{
				ParseTokenFunc: func(ctx context.Context, token string) (*jwt.RegisteredClaims, error) {
					return &jwt.RegisteredClaims{
						ID:        "shared123",
						Subject:   "user789",
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					}, nil
				},
			},
			&mockHasher{},
		)

		// Token should be blacklisted in second instance too
		_, err = biz2.IntrospectToken(ctx, "shared.token")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been revoked")
	})
}

func TestRedisTokenManager_EdgeCases(t *testing.T) {
	ctx := context.Background()

	// Setup Redis test container
	redisTestContainer := helpers.SetupRedisTestContainer(ctx, t)
	defer func() {
		err := redisTestContainer.Cleanup(ctx)
		if err != nil {
			t.Logf("Failed to cleanup Redis container: %v", err)
		}
	}()

	cleanup := redisTestContainer.SetRedisURL()
	defer cleanup()

	tokenManager := helpers.NewRedisTokenManager()

	t.Run("EmptyToken", func(t *testing.T) {
		err := tokenManager.BlacklistToken(ctx, "", time.Minute)
		assert.NoError(t, err) // Should handle gracefully

		isBlacklisted := tokenManager.IsTokenBlacklisted(ctx, "")
		assert.False(t, isBlacklisted)
	})

	t.Run("VeryLongToken", func(t *testing.T) {
		longToken := make([]byte, 10000)
		for i := range longToken {
			longToken[i] = 'a'
		}
		token := string(longToken)

		err := tokenManager.BlacklistToken(ctx, token, time.Minute)
		assert.NoError(t, err)

		isBlacklisted := tokenManager.IsTokenBlacklisted(ctx, token)
		assert.True(t, isBlacklisted)
	})

	t.Run("ZeroTTL", func(t *testing.T) {
		token := "zero.ttl.token"

		err := tokenManager.BlacklistToken(ctx, token, 0)
		assert.NoError(t, err)

		// Token with zero TTL should expire immediately
		isBlacklisted := tokenManager.IsTokenBlacklisted(ctx, token)
		assert.False(t, isBlacklisted)
	})
}
