package cmd

import (
	"context"
	"demo-service/common"
	helper "demo-service/helpers"

	"github.com/golang-jwt/jwt/v5"
	sctx "github.com/viettranx/service-context"
)

// CustomJWTComponent wraps our custom JWT provider to be compatible with service context
type CustomJWTComponent struct {
	id       string
	provider common.JWTProvider
}

func NewCustomJWTComponent(id string) *CustomJWTComponent {
	return &CustomJWTComponent{
		id:       id,
		provider: helper.NewCustomJWTProvider(),
	}
}

func (c *CustomJWTComponent) ID() string {
	return c.id
}

func (c *CustomJWTComponent) InitFlags() {
	// No flags needed for our custom JWT provider
}

func (c *CustomJWTComponent) IssueToken(ctx context.Context, id, sub string) (string, int, error) {
	return c.provider.IssueToken(ctx, id, sub)
}

func (c *CustomJWTComponent) ParseToken(ctx context.Context, tokenString string) (*jwt.RegisteredClaims, error) {
	return c.provider.ParseToken(ctx, tokenString)
}

func (c *CustomJWTComponent) Activate(serviceCtx sctx.ServiceContext) error {
	// Registration skipped or update this if you find the correct method in serviceCtx
	return nil
}

func (c *CustomJWTComponent) Stop() error {
	// No cleanup needed
	return nil
}
