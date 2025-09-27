package helpers

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func setEnvVars(vars map[string]string) func() {
	old := make(map[string]string)
	for k, v := range vars {
		old[k] = os.Getenv(k)
		os.Setenv(k, v)
	}
	return func() {
		for k, v := range old {
			os.Setenv(k, v)
		}
	}
}

func TestCustomJWTProvider_IssueAndParseToken(t *testing.T) {
	cleanup := setEnvVars(map[string]string{
		"JWT_SECRET":              "test-secret",
		"JWT_ACCESS_TOKEN_EXPIRY": "1m",
	})
	defer cleanup()

	provider := NewCustomJWTProvider()
	ctx := context.Background()
	token, exp, err := provider.IssueToken(ctx, "123", "user@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Equal(t, 60, exp)

	claims, err := provider.ParseToken(ctx, token)
	assert.NoError(t, err)
	assert.Equal(t, "123", claims.ID)
	assert.Equal(t, "user@example.com", claims.Subject)
}

func TestCustomJWTProvider_IssueRefreshToken(t *testing.T) {
	cleanup := setEnvVars(map[string]string{
		"JWT_SECRET":               "test-secret",
		"JWT_REFRESH_TOKEN_EXPIRY": "2h",
	})
	defer cleanup()

	provider := NewCustomJWTProvider()
	ctx := context.Background()
	token, exp, err := provider.IssueRefreshToken(ctx, "456", "refresh@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Equal(t, 7200, exp)
}

func TestCustomJWTProvider_ParseToken_InvalidToken(t *testing.T) {
	cleanup := setEnvVars(map[string]string{
		"JWT_SECRET": "test-secret",
	})
	defer cleanup()

	provider := NewCustomJWTProvider()
	ctx := context.Background()
	_, err := provider.ParseToken(ctx, "invalid.token.value")
	assert.Error(t, err)
}

func TestCustomJWTProvider_GetTokenInfo(t *testing.T) {
	cleanup := setEnvVars(map[string]string{
		"JWT_SECRET": "test-secret",
	})
	defer cleanup()

	provider := NewCustomJWTProvider()
	ctx := context.Background()
	token, _, err := provider.IssueToken(ctx, "789", "info@example.com")
	assert.NoError(t, err)

	claims, err := provider.GetTokenInfo(token)
	assert.NoError(t, err)
	assert.Equal(t, "789", claims.ID)
	assert.Equal(t, "info@example.com", claims.Subject)
}

func TestParseDurationWithFallback_InvalidFormat(t *testing.T) {
	cleanup := setEnvVars(map[string]string{
		"TEST_DURATION": "notaduration",
	})
	defer cleanup()
	d := parseDurationWithFallback("TEST_DURATION", 42*time.Second)
	assert.Equal(t, 42*time.Second, d)
}

func TestCustomJWTProvider_ParseToken_Expired(t *testing.T) {
	cleanup := setEnvVars(map[string]string{
		"JWT_SECRET":              "test-secret",
		"JWT_ACCESS_TOKEN_EXPIRY": "-1s",
		"TOKEN_EXPIRY_TOLERANCE":  "0s",
	})
	defer cleanup()

	provider := NewCustomJWTProvider()
	ctx := context.Background()
	token, _, err := provider.IssueToken(ctx, "expired", "expired@example.com")
	assert.NoError(t, err)
	_, err = provider.ParseToken(ctx, token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}
