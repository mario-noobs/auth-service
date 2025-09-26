package business

import (
	"context"
	"demo-service/common"
	"demo-service/helpers"

	"demo-service/proto/pb"
	"demo-service/services/auth/entity"
	"log/slog"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/uuid"
	"github.com/viettranx/service-context/core"
)

var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

type AuthRepository interface {
	AddNewAuth(ctx context.Context, data *entity.Auth) error
	GetAuth(ctx context.Context, email string) (*entity.Auth, error)
}

type UserRepository interface {
	CreateUser(ctx context.Context, firstName, lastName, email string) (newId int, err error)
}

type Hasher interface {
	RandomStr(length int) (string, error)
	HashPassword(salt, password string) (string, error)
	CompareHashPassword(hashedPassword, salt, password string) bool
}

type business struct {
	repository     AuthRepository
	userRepository UserRepository
	jwtProvider    common.JWTProvider
	hasher         Hasher
	time           helpers.Timer
	tokenManager   *helpers.RedisTokenManager
}

func NewBusiness(repository AuthRepository, userRepository UserRepository,
	jwtProvider common.JWTProvider, hasher Hasher) *business {
	return &business{
		repository:     repository,
		userRepository: userRepository,
		jwtProvider:    jwtProvider,
		hasher:         hasher,
		tokenManager:   helpers.NewRedisTokenManager(),
	}
}

func (biz *business) Login(ctx context.Context, data *pb.AuthEmailPassword) (*pb.TokenResponse, error) {
	var method = "Login_Business"
	biz.time.Start()
	logger.Info("request", "method", method)

	if err := data.Validate(); err != nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrBadRequest.WithError(err.Error())
	}

	authData, err := biz.repository.GetAuth(ctx, data.Email)

	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrBadRequest.WithError(entity.ErrLoginFailed.Error()).WithDebug(err.Error())
	}

	if !biz.hasher.CompareHashPassword(authData.Password, authData.Salt, data.Password) {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrBadRequest.WithError(entity.ErrLoginFailed.Error())
	}

	uid := core.NewUID(uint32(authData.UserId), 1, 1)
	sub := uid.String()
	tid := uuid.New().String()

	accessTokenStr, accessExpSecs, err := biz.jwtProvider.IssueToken(ctx, tid, sub)
	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrInternalServerError.WithError(entity.ErrLoginFailed.Error()).WithDebug(err.Error())
	}

	refreshTokenStr, refreshExpSecs, err := biz.jwtProvider.IssueRefreshToken(ctx, tid+"_refresh", sub)
	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrInternalServerError.WithError(entity.ErrLoginFailed.Error()).WithDebug(err.Error())
	}

	accessToken := pb.Token{
		Token:     accessTokenStr,
		ExpiredIn: int32(accessExpSecs),
	}

	refreshToken := pb.Token{
		Token:     refreshTokenStr,
		ExpiredIn: int32(refreshExpSecs),
	}

	logger.Info("response", "method", method, "data", accessTokenStr, "ms", biz.time.End())

	return &pb.TokenResponse{
		AccessToken:  &accessToken,
		RefreshToken: &refreshToken,
	}, nil
}

func (biz *business) Register(ctx context.Context, data *pb.AuthRegister) (*empty.Empty, error) {
	var method = "Register_Business"
	biz.time.Start()
	logger.Info("request", "method", method)

	if err := data.Validate(); err != nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrBadRequest.WithError(err.Error())
	}

	_, err := biz.repository.GetAuth(ctx, data.AuthEmailPassword.Email)

	if err == nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrBadRequest.WithError(entity.ErrEmailHasExisted.Error())
	} else if err != core.ErrRecordNotFound {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrInternalServerError.WithError(entity.ErrCannotRegister.Error()).WithDebug(err.Error())
	}

	newUserId, err := biz.userRepository.CreateUser(ctx, data.FirstName, data.LastName, data.AuthEmailPassword.Email)

	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrInternalServerError.WithError(entity.ErrCannotRegister.Error()).WithDebug(err.Error())
	}

	salt, err := biz.hasher.RandomStr(16)

	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrInternalServerError.WithError(entity.ErrCannotRegister.Error()).WithDebug(err.Error())
	}

	passHashed, err := biz.hasher.HashPassword(salt, data.AuthEmailPassword.Password)

	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrInternalServerError.WithError(entity.ErrCannotRegister.Error()).WithDebug(err.Error())
	}

	newAuth := entity.NewAuthWithEmailPassword(newUserId, data.AuthEmailPassword.Email, salt, passHashed)

	if err := biz.repository.AddNewAuth(ctx, &newAuth); err != nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrInternalServerError.WithError(entity.ErrCannotRegister.Error()).WithDebug(err.Error())
	}

	logger.Info("response", "method", method, "data", true, "ms", biz.time.End())

	return &empty.Empty{}, nil
}

func (biz *business) IntrospectToken(ctx context.Context, accessToken string) (*jwt.RegisteredClaims, error) {
	var method = "IntrospectToken_Business"
	biz.time.Start()
	logger.Info("request", "method", method)

	// First check if token is blacklisted
	if biz.tokenManager.IsTokenBlacklisted(ctx, accessToken) {
		logger.Error("response", "method", method, "err", "token blacklisted", "ms", biz.time.End())
		return nil, core.ErrUnauthorized.WithError("token has been revoked")
	}

	claims, err := biz.jwtProvider.ParseToken(ctx, accessToken)

	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrUnauthorized.WithDebug(err.Error())
	}
	logger.Info("response", "method", method, "data", claims, "ms", biz.time.End())
	return claims, nil
}

func (biz *business) Logout(ctx context.Context, accessToken string) (*empty.Empty, error) {
	var method = "Logout_Business"
	biz.time.Start()
	logger.Info("request", "method", method)

	// Parse token to get expiration time for blacklist TTL
	claims, err := biz.jwtProvider.ParseToken(ctx, accessToken)
	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrBadRequest.WithError("invalid token")
	}

	// Calculate remaining token lifetime
	remainingTime := claims.ExpiresAt.Sub(time.Now())
	if remainingTime <= 0 {
		// Token already expired, no need to blacklist
		logger.Info("response", "method", method, "data", "token already expired", "ms", biz.time.End())
		return &empty.Empty{}, nil
	}

	// Blacklist the token for its remaining lifetime
	err = biz.tokenManager.BlacklistToken(ctx, accessToken, remainingTime)
	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrInternalServerError.WithError("logout failed").WithDebug(err.Error())
	}

	logger.Info("response", "method", method, "data", "logged out successfully", "ms", biz.time.End())
	return &empty.Empty{}, nil
}

func (biz *business) RefreshToken(ctx context.Context, refreshToken string) (*pb.TokenResponse, error) {
	var method = "RefreshToken_Business"
	biz.time.Start()
	logger.Info("request", "method", method)

	// Validate the refresh token
	claims, err := biz.jwtProvider.ParseToken(ctx, refreshToken)
	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrUnauthorized.WithError("invalid refresh token")
	}

	// Check if token is blacklisted
	if biz.tokenManager.IsTokenBlacklisted(ctx, refreshToken) {
		logger.Error("response", "method", method, "err", "token is blacklisted", "ms", biz.time.End())
		return nil, core.ErrUnauthorized.WithError("refresh token has been revoked")
	}

	// Generate new access token with same subject
	newTid := uuid.New().String()
	accessTokenStr, accessExpSecs, err := biz.jwtProvider.IssueToken(ctx, newTid, claims.Subject)
	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrInternalServerError.WithError("failed to generate new access token").WithDebug(err.Error())
	}

	// Generate new refresh token (optional - you can reuse old one or issue new one)
	refreshTokenStr, refreshExpSecs, err := biz.jwtProvider.IssueRefreshToken(ctx, newTid+"_refresh", claims.Subject)
	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrInternalServerError.WithError("failed to generate new refresh token").WithDebug(err.Error())
	}

	// Blacklist the old refresh token to prevent reuse
	remainingTime := claims.ExpiresAt.Sub(time.Now())
	if remainingTime > 0 {
		err = biz.tokenManager.BlacklistToken(ctx, refreshToken, remainingTime)
		if err != nil {
			logger.Warn("response", "method", method, "warning", "failed to blacklist old refresh token", "err", err)
		}
	}

	accessToken := pb.Token{
		Token:     accessTokenStr,
		ExpiredIn: int32(accessExpSecs),
	}

	newRefreshToken := pb.Token{
		Token:     refreshTokenStr,
		ExpiredIn: int32(refreshExpSecs),
	}

	logger.Info("response", "method", method, "data", "tokens refreshed successfully", "ms", biz.time.End())
	return &pb.TokenResponse{
		AccessToken:  &accessToken,
		RefreshToken: &newRefreshToken,
	}, nil
}
