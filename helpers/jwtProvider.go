package helpers

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// getEnvOrDefault returns environment variable value or default if not set
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// parseDurationWithFallback parses duration string with fallback to default
func parseDurationWithFallback(envKey string, defaultDuration time.Duration) time.Duration {
	if durationStr := os.Getenv(envKey); durationStr != "" {
		if duration, err := time.ParseDuration(durationStr); err == nil {
			return duration
		}
		log.Printf("Warning: Invalid duration format for %s: %s, using default", envKey, durationStr)
	}
	return defaultDuration
}

// getTokenExpiry returns token expiration duration from environment variables
func getTokenExpiry(tokenType string) time.Duration {
	switch strings.ToLower(tokenType) {
	case "access":
		return parseDurationWithFallback("JWT_ACCESS_TOKEN_EXPIRY", 15*time.Minute)
	case "refresh":
		return parseDurationWithFallback("JWT_REFRESH_TOKEN_EXPIRY", 7*24*time.Hour)
	default:
		return parseDurationWithFallback("JWT_ACCESS_TOKEN_EXPIRY", 15*time.Minute)
	}
}

// CustomJWTProvider implements the JWTProvider interface with configurable expiration
type CustomJWTProvider struct {
	secretKey string
}

// NewCustomJWTProvider creates a new JWT provider instance
func NewCustomJWTProvider() *CustomJWTProvider {
	secretKey := getEnvOrDefault("JWT_SECRET", "very-important-please-change-it!")
	if secretKey == "very-important-please-change-it!" {
		log.Printf("Warning: Using default JWT secret. Please set JWT_SECRET environment variable.")
	}
	return &CustomJWTProvider{
		secretKey: secretKey,
	}
}

// IssueToken creates a new JWT token with configurable expiration
func (p *CustomJWTProvider) IssueToken(ctx context.Context, id, sub string) (token string, expSecs int, err error) {
	accessTokenExpiry := getTokenExpiry("access")
	now := time.Now()
	expiresAt := now.Add(accessTokenExpiry)

	claims := jwt.RegisteredClaims{
		ID:        id,
		Subject:   sub,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		NotBefore: jwt.NewNumericDate(now),
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := jwtToken.SignedString([]byte(p.secretKey))
	if err != nil {
		log.Printf("Error signing JWT token: %v", err)
		return "", 0, fmt.Errorf("failed to sign token: %w", err)
	}

	expSecsInt := int(accessTokenExpiry.Seconds())
	log.Printf("JWT token issued for subject %s, expires in %d seconds", sub, expSecsInt)

	return tokenString, expSecsInt, nil
}

// ParseToken validates and parses a JWT token
func (p *CustomJWTProvider) ParseToken(ctx context.Context, tokenString string) (claims *jwt.RegisteredClaims, err error) {
	// Remove "Bearer " prefix if present
	if strings.HasPrefix(tokenString, "Bearer ") {
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	}

	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(p.secretKey), nil
	})

	if err != nil {
		log.Printf("Error parsing JWT token: %v", err)
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Check expiration with tolerance
	tolerance := parseDurationWithFallback("TOKEN_EXPIRY_TOLERANCE", 5*time.Minute)
	now := time.Now()

	if claims.ExpiresAt != nil && now.After(claims.ExpiresAt.Add(tolerance)) {
		return nil, fmt.Errorf("token is expired")
	}

	log.Printf("JWT token validated successfully for subject: %s", claims.Subject)
	return claims, nil
}

// IssueRefreshToken creates a refresh token with longer expiration
func (p *CustomJWTProvider) IssueRefreshToken(ctx context.Context, id, sub string) (token string, expSecs int, err error) {
	refreshTokenExpiry := getTokenExpiry("refresh")
	now := time.Now()
	expiresAt := now.Add(refreshTokenExpiry)

	claims := jwt.RegisteredClaims{
		ID:        id,
		Subject:   sub,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		NotBefore: jwt.NewNumericDate(now),
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := jwtToken.SignedString([]byte(p.secretKey))
	if err != nil {
		return "", 0, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	expSecsInt := int(refreshTokenExpiry.Seconds())
	log.Printf("Refresh token issued for subject %s, expires in %d seconds", sub, expSecsInt)

	return tokenString, expSecsInt, nil
}

// GetTokenInfo extracts information from a token without full validation
func (p *CustomJWTProvider) GetTokenInfo(tokenString string) (*jwt.RegisteredClaims, error) {
	if strings.HasPrefix(tokenString, "Bearer ") {
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	}

	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &jwt.RegisteredClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}
