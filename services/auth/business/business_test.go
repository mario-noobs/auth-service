package business

import (
	"context"
	"demo-service/proto/pb"
	"demo-service/services/auth/entity"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/viettranx/service-context/core"
	"testing"
)

// Mocking AuthRepository
type MockAuthRepository struct {
	mock.Mock
}

func (m *MockAuthRepository) AddNewAuth(ctx context.Context, data *entity.Auth) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

func (m *MockAuthRepository) GetAuth(ctx context.Context, email string) (*entity.Auth, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(*entity.Auth), args.Error(1)
}

// Mocking UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) CreateUser(ctx context.Context, firstName, lastName, email string) (newId int, err error) {
	args := m.Called(ctx, firstName, lastName, email)
	return args.Int(0), args.Error(1)
}

// Mocking Hasher
type MockHasher struct {
	mock.Mock
}

func (m *MockHasher) RandomStr(length int) (string, error) {
	args := m.Called(length)
	return args.String(0), args.Error(1)
}

func (m *MockHasher) HashPassword(salt, password string) (string, error) {
	args := m.Called(salt, password)
	return args.String(0), args.Error(1)
}

func (m *MockHasher) CompareHashPassword(hashedPassword, salt, password string) bool {
	args := m.Called(hashedPassword, salt, password)
	return args.Bool(0)
}

// Mocking JWTProvider
type MockJWTProvider struct {
	mock.Mock
}

func (m *MockJWTProvider) IssueToken(ctx context.Context, id, sub string) (token string, expSecs int, err error) {
	args := m.Called(ctx, id, sub)
	return args.String(0), args.Get(1).(int), args.Error(2)
}

func (m *MockJWTProvider) ParseToken(ctx context.Context, accessToken string) (*jwt.RegisteredClaims, error) {
	args := m.Called(ctx, accessToken)
	return args.Get(0).(*jwt.RegisteredClaims), args.Error(1)
}

func TestAuthEmailPassword_Validate(t *testing.T) {
	tests := []struct {
		name      string
		input     *pb.AuthEmailPassword
		expectErr bool
	}{
		{
			name:      "valid input",
			input:     &pb.AuthEmailPassword{Email: "test@example.com", Password: "password"},
			expectErr: false,
		},
		{
			name:      "missing email",
			input:     &pb.AuthEmailPassword{Email: "", Password: "password"},
			expectErr: true,
		},
		{
			name:      "missing password",
			input:     &pb.AuthEmailPassword{Email: "test@example.com", Password: ""},
			expectErr: true,
		},
		{
			name:      "invalid email format",
			input:     &pb.AuthEmailPassword{Email: "invalid-email", Password: "password"},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthRegister_Validate(t *testing.T) {
	tests := []struct {
		name      string
		input     *pb.AuthRegister
		expectErr bool
	}{
		{
			name:      "valid input",
			input:     &pb.AuthRegister{FirstName: "John", LastName: "Doe", AuthEmailPassword: &pb.AuthEmailPassword{Email: "test@example.com", Password: "password"}},
			expectErr: false,
		},
		{
			name:      "missing first name",
			input:     &pb.AuthRegister{FirstName: "", LastName: "Doe", AuthEmailPassword: &pb.AuthEmailPassword{Email: "test@example.com", Password: "password"}},
			expectErr: true,
		},
		{
			name:      "missing last name",
			input:     &pb.AuthRegister{FirstName: "John", LastName: "", AuthEmailPassword: &pb.AuthEmailPassword{Email: "test@example.com", Password: "password"}},
			expectErr: true,
		},
		{
			name:      "missing email and password",
			input:     &pb.AuthRegister{FirstName: "John", LastName: "Doe", AuthEmailPassword: nil},
			expectErr: true,
		},
		{
			name:      "invalid email format in AuthEmailPassword",
			input:     &pb.AuthRegister{FirstName: "John", LastName: "Doe", AuthEmailPassword: &pb.AuthEmailPassword{Email: "invalid-email", Password: "password"}},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLogin_Success(t *testing.T) {
	authRepo := new(MockAuthRepository)
	userRepo := new(MockUserRepository)
	jwtProvider := new(MockJWTProvider)
	hasher := new(MockHasher)

	biz := NewBusiness(authRepo, userRepo, jwtProvider, hasher)

	// Setup mock expectations
	email := "test@example.com"
	password := "password"
	salt := "random_salt"
	hashedPassword := "hashed_password"
	authData := &entity.Auth{Email: email, Password: hashedPassword, Salt: salt, UserId: 1}

	authRepo.On("GetAuth", mock.Anything, email).Return(authData, nil)
	hasher.On("CompareHashPassword", hashedPassword, salt, password).Return(true)
	jwtProvider.On("IssueToken", mock.Anything, mock.Anything, mock.Anything).Return("token_string", 3600, nil)

	// Call the method
	tokenResponse, err := biz.Login(context.Background(), &pb.AuthEmailPassword{Email: email, Password: password})

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, tokenResponse)
	assert.Equal(t, "token_string", tokenResponse.AccessToken.Token)

	// Assert expectations
	authRepo.AssertExpectations(t)
	hasher.AssertExpectations(t)
	jwtProvider.AssertExpectations(t)
}

func TestLogin_EmailNotExist(t *testing.T) {
	authRepo := new(MockAuthRepository)
	userRepo := new(MockUserRepository)
	jwtProvider := new(MockJWTProvider)
	hasher := new(MockHasher)

	biz := NewBusiness(authRepo, userRepo, jwtProvider, hasher)

	// Setup mock expectations
	email := "test@example.com"
	password := "password"
	salt := "random_salt"
	hashedPassword := "hashed_password"
	//authData := &entity.Auth{Email: email, Password: hashedPassword, Salt: salt, UserId: 1}

	authRepo.On("GetAuth", mock.Anything, email).Return(&entity.Auth{}, entity.ErrLoginFailed)
	hasher.On("CompareHashPassword", hashedPassword, salt, password).Return(true)
	jwtProvider.On("IssueToken", mock.Anything, mock.Anything, mock.Anything).Return("token_string", 3600, nil)

	// Call the method
	_, err := biz.Login(context.Background(), &pb.AuthEmailPassword{Email: email, Password: password})

	// Assertions
	assert.Error(t, err)
	assert.Equal(t, err.Error(), entity.ErrLoginFailed.Error())
	//assert.Equal(t, "token_string", tokenResponse.AccessToken.Token)

	// Assert expectations
	authRepo.AssertExpectations(t)
	//hasher.AssertExpectations(t)
	//jwtProvider.AssertExpectations(t)
}

func TestLogin_WrongPasswordHash(t *testing.T) {
	authRepo := new(MockAuthRepository)
	userRepo := new(MockUserRepository)
	jwtProvider := new(MockJWTProvider)
	hasher := new(MockHasher)

	biz := NewBusiness(authRepo, userRepo, jwtProvider, hasher)

	// Setup mock expectations
	email := "test@example.com"
	password := "password"
	salt := "random_salt"
	hashedPassword := "hashed_password"
	authData := &entity.Auth{Email: email, Password: hashedPassword, Salt: salt, UserId: 1}

	authRepo.On("GetAuth", mock.Anything, email).Return(authData, nil)
	hasher.On("CompareHashPassword", hashedPassword, salt, password).Return(false)
	jwtProvider.On("IssueToken", mock.Anything, mock.Anything, mock.Anything).Return("token_string", 3600, nil)

	// Call the method
	_, err := biz.Login(context.Background(), &pb.AuthEmailPassword{Email: email, Password: password})

	// Assertions
	assert.Error(t, err)
	assert.Equal(t, err.Error(), entity.ErrLoginFailed.Error())
	//assert.Equal(t, "token_string", tokenResponse.AccessToken.Token)

	// Assert expectations
	authRepo.AssertExpectations(t)
	hasher.AssertExpectations(t)
	//jwtProvider.AssertExpectations(t)
}

func TestRegister_Success(t *testing.T) {
	authRepo := new(MockAuthRepository)
	userRepo := new(MockUserRepository)
	jwtProvider := new(MockJWTProvider)
	hasher := new(MockHasher)

	biz := NewBusiness(authRepo, userRepo, jwtProvider, hasher)

	// Setup mock expectations
	email := "test@example.com"
	firstName := "John"
	lastName := "Doe"
	password := "password"
	salt := "random_salt"
	hashedPassword := "hashed_password"

	authRepo.On("GetAuth", mock.Anything, email).Return(&entity.Auth{}, core.ErrRecordNotFound)
	userRepo.On("CreateUser", mock.Anything, firstName, lastName, email).Return(1, nil)
	hasher.On("RandomStr", 16).Return(salt, nil)
	hasher.On("HashPassword", salt, password).Return(hashedPassword, nil)
	authRepo.On("AddNewAuth", mock.Anything, mock.Anything).Return(nil)

	// Call the method
	_, err := biz.Register(context.Background(), &pb.AuthRegister{
		FirstName:         firstName,
		LastName:          lastName,
		AuthEmailPassword: &pb.AuthEmailPassword{Email: email, Password: password},
	})

	// Assertions
	assert.NoError(t, err)

	// Assert expectations
	authRepo.AssertExpectations(t)
	userRepo.AssertExpectations(t)
	hasher.AssertExpectations(t)
}

func TestRegister_UserExisted(t *testing.T) {
	authRepo := new(MockAuthRepository)
	userRepo := new(MockUserRepository)
	jwtProvider := new(MockJWTProvider)
	hasher := new(MockHasher)

	biz := NewBusiness(authRepo, userRepo, jwtProvider, hasher)

	// Setup mock expectations
	email := "test@example.com"
	firstName := "John"
	lastName := "Doe"
	password := "password"
	salt := "random_salt"
	hashedPassword := "hashed_password"

	authRepo.On("GetAuth", mock.Anything, email).Return(&entity.Auth{}, entity.ErrEmailHasExisted)
	userRepo.On("CreateUser", mock.Anything, firstName, lastName, email).Return(1, nil)
	hasher.On("RandomStr", 16).Return(salt, nil)
	hasher.On("HashPassword", salt, password).Return(hashedPassword, nil)
	authRepo.On("AddNewAuth", mock.Anything, mock.Anything).Return(nil)

	// Call the method
	_, err := biz.Register(context.Background(), &pb.AuthRegister{
		FirstName:         firstName,
		LastName:          lastName,
		AuthEmailPassword: &pb.AuthEmailPassword{Email: email, Password: password},
	})

	// Assertions
	assert.Error(t, err)
	assert.Equal(t, err.Error(), entity.ErrCannotRegister.Error())

	// Assert expectations
	//authRepo.AssertExpectations(t)
	//userRepo.AssertExpectations(t)
	//hasher.AssertExpectations(t)
}

func TestIntrospectToken_Success(t *testing.T) {
	jwtProvider := new(MockJWTProvider)
	biz := NewBusiness(nil, nil, jwtProvider, nil)

	// Setup mock expectations
	accessToken := "valid_token"
	claims := &jwt.RegisteredClaims{Subject: "user_id"}
	jwtProvider.On("ParseToken", mock.Anything, accessToken).Return(claims, nil)

	// Call the method
	result, err := biz.IntrospectToken(context.Background(), accessToken)

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, claims, result)

	// Assert expectations
	jwtProvider.AssertExpectations(t)
}

func TestIntrospectToken_InvalidParse(t *testing.T) {
	jwtProvider := new(MockJWTProvider)
	biz := NewBusiness(nil, nil, jwtProvider, nil)

	// Setup mock expectations
	accessToken := "invalid_token"
	expectedError := errors.New("The request could not be authorized") //

	//claims := &jwt.RegisteredClaims{Subject: "user_id"}
	jwtProvider.On("ParseToken", mock.Anything, accessToken).Return(&jwt.RegisteredClaims{}, expectedError)

	// Call the method
	_, err := biz.IntrospectToken(context.Background(), accessToken)

	// Assertions
	assert.Error(t, err)
	assert.Equal(t, err.Error(), expectedError.Error())

	// Assert expectations
	jwtProvider.AssertExpectations(t)
}
