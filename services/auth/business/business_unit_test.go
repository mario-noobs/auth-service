package business

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/viettranx/service-context/core"
	"google.golang.org/protobuf/types/known/emptypb"

	"demo-service/helpers"
	"demo-service/proto/pb"
	"demo-service/services/auth/entity"
)

// --- Mocks ---
type mockAuthRepo struct {
	AddNewAuthFunc func(ctx context.Context, data *entity.Auth) error
	GetAuthFunc    func(ctx context.Context, email string) (*entity.Auth, error)
}

func (m *mockAuthRepo) AddNewAuth(ctx context.Context, data *entity.Auth) error {
	return m.AddNewAuthFunc(ctx, data)
}
func (m *mockAuthRepo) GetAuth(ctx context.Context, email string) (*entity.Auth, error) {
	return m.GetAuthFunc(ctx, email)
}

type mockUserRepo struct {
	CreateUserFunc func(ctx context.Context, firstName, lastName, email string) (int, error)
}

func (m *mockUserRepo) CreateUser(ctx context.Context, firstName, lastName, email string) (int, error) {
	return m.CreateUserFunc(ctx, firstName, lastName, email)
}

type mockHasher struct {
	RandomStrFunc           func(length int) (string, error)
	HashPasswordFunc        func(salt, password string) (string, error)
	CompareHashPasswordFunc func(hashedPassword, salt, password string) bool
}

func (m *mockHasher) RandomStr(length int) (string, error) {
	return m.RandomStrFunc(length)
}
func (m *mockHasher) HashPassword(salt, password string) (string, error) {
	return m.HashPasswordFunc(salt, password)
}
func (m *mockHasher) CompareHashPassword(hashedPassword, salt, password string) bool {
	return m.CompareHashPasswordFunc(hashedPassword, salt, password)
}

type mockJWTProvider struct {
	IssueTokenFunc        func(ctx context.Context, id, sub string) (string, int, error)
	IssueRefreshTokenFunc func(ctx context.Context, id, sub string) (string, int, error)
	ParseTokenFunc        func(ctx context.Context, token string) (*jwt.RegisteredClaims, error)
}

func (m *mockJWTProvider) IssueToken(ctx context.Context, id, sub string) (string, int, error) {
	return m.IssueTokenFunc(ctx, id, sub)
}
func (m *mockJWTProvider) IssueRefreshToken(ctx context.Context, id, sub string) (string, int, error) {
	return m.IssueRefreshTokenFunc(ctx, id, sub)
}
func (m *mockJWTProvider) ParseToken(ctx context.Context, token string) (*jwt.RegisteredClaims, error) {
	return m.ParseTokenFunc(ctx, token)
}

// Helper function to create business for testing
func createTestBusiness(authRepo AuthRepository, userRepo UserRepository, jwtProvider *mockJWTProvider, hasher Hasher) *business {
	biz := NewBusiness(authRepo, userRepo, jwtProvider, hasher)
	biz.time = helpers.Timer{}
	// RedisTokenManager with nil client will work without Redis (see the implementation)
	biz.tokenManager = helpers.NewRedisTokenManager() // This will create with nil client if Redis is unavailable
	return biz
}

// --- Tests ---
func TestBusiness_Login_Success(t *testing.T) {
	biz := createTestBusiness(
		&mockAuthRepo{
			GetAuthFunc: func(ctx context.Context, email string) (*entity.Auth, error) {
				return &entity.Auth{UserId: 1, Password: "hashed", Salt: "salt"}, nil
			},
		},
		&mockUserRepo{},
		&mockJWTProvider{
			IssueTokenFunc:        func(ctx context.Context, id, sub string) (string, int, error) { return "access", 60, nil },
			IssueRefreshTokenFunc: func(ctx context.Context, id, sub string) (string, int, error) { return "refresh", 120, nil },
		},
		&mockHasher{
			CompareHashPasswordFunc: func(hashed, salt, password string) bool { return true },
		},
	)

	ctx := context.Background()
	resp, err := biz.Login(ctx, &pb.AuthEmailPassword{Email: "test@example.com", Password: "password123"})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.AccessToken)
	assert.NotNil(t, resp.RefreshToken)
	assert.Equal(t, "access", resp.AccessToken.Token)
	assert.Equal(t, "refresh", resp.RefreshToken.Token)
}

func TestBusiness_Login_Fail_InvalidPassword(t *testing.T) {
	biz := createTestBusiness(
		&mockAuthRepo{
			GetAuthFunc: func(ctx context.Context, email string) (*entity.Auth, error) {
				return &entity.Auth{UserId: 1, Password: "hashed", Salt: "salt"}, nil
			},
		},
		&mockUserRepo{},
		&mockJWTProvider{},
		&mockHasher{
			CompareHashPasswordFunc: func(hashed, salt, password string) bool { return false },
		},
	)

	ctx := context.Background()
	resp, err := biz.Login(ctx, &pb.AuthEmailPassword{Email: "test@example.com", Password: "wrongpassword"})
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestBusiness_Register_Success(t *testing.T) {
	biz := createTestBusiness(
		&mockAuthRepo{
			GetAuthFunc: func(ctx context.Context, email string) (*entity.Auth, error) {
				return nil, core.ErrRecordNotFound
			},
			AddNewAuthFunc: func(ctx context.Context, data *entity.Auth) error { return nil },
		},
		&mockUserRepo{
			CreateUserFunc: func(ctx context.Context, firstName, lastName, email string) (int, error) { return 2, nil },
		},
		&mockJWTProvider{},
		&mockHasher{
			RandomStrFunc:    func(length int) (string, error) { return "salt", nil },
			HashPasswordFunc: func(salt, password string) (string, error) { return "hashed", nil },
		},
	)

	ctx := context.Background()
	resp, err := biz.Register(ctx, &pb.AuthRegister{
		FirstName:         "John",
		LastName:          "Doe",
		AuthEmailPassword: &pb.AuthEmailPassword{Email: "john.doe@example.com", Password: "password123"},
	})
	assert.NoError(t, err)
	assert.IsType(t, &emptypb.Empty{}, resp)
}

func TestBusiness_Register_Fail_EmailExists(t *testing.T) {
	biz := createTestBusiness(
		&mockAuthRepo{
			GetAuthFunc: func(ctx context.Context, email string) (*entity.Auth, error) {
				return &entity.Auth{UserId: 1}, nil // Email already exists
			},
		},
		&mockUserRepo{},
		&mockJWTProvider{},
		&mockHasher{},
	)

	ctx := context.Background()
	resp, err := biz.Register(ctx, &pb.AuthRegister{
		FirstName:         "Jane",
		LastName:          "Smith",
		AuthEmailPassword: &pb.AuthEmailPassword{Email: "existing@test.com", Password: "password123"},
	})
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestBusiness_IntrospectToken_Success(t *testing.T) {
	expectedClaims := &jwt.RegisteredClaims{
		ID:      "token123",
		Subject: "user456",
	}

	biz := createTestBusiness(
		&mockAuthRepo{},
		&mockUserRepo{},
		&mockJWTProvider{
			ParseTokenFunc: func(ctx context.Context, token string) (*jwt.RegisteredClaims, error) {
				return expectedClaims, nil
			},
		},
		&mockHasher{},
	)

	ctx := context.Background()
	claims, err := biz.IntrospectToken(ctx, "valid.token.here")
	assert.NoError(t, err)
	assert.Equal(t, expectedClaims, claims)
}
