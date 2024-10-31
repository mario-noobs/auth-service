package business

import (
	"context"
	"demo-service/common"
	"demo-service/helpers"
	"demo-service/proto/pb"
	"demo-service/services/auth/entity"
	"github.com/golang-jwt/jwt/v5"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/uuid"
	"github.com/viettranx/service-context/core"
	"log/slog"
	"os"
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
}

func NewBusiness(repository AuthRepository, userRepository UserRepository,
	jwtProvider common.JWTProvider, hasher Hasher) *business {
	return &business{
		repository:     repository,
		userRepository: userRepository,
		jwtProvider:    jwtProvider,
		hasher:         hasher,
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

	tokenStr, expSecs, err := biz.jwtProvider.IssueToken(ctx, tid, sub)

	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrInternalServerError.WithError(entity.ErrLoginFailed.Error()).WithDebug(err.Error())
	}

	token := pb.Token{
		Token:     tokenStr,
		ExpiredIn: int32(expSecs),
	}

	logger.Info("response", "method", method, "data", tokenStr, "ms", biz.time.End())

	return &pb.TokenResponse{
		AccessToken: &token,
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
	var method = "Register_Business"
	biz.time.Start()
	logger.Info("request", "method", method)

	claims, err := biz.jwtProvider.ParseToken(ctx, accessToken)

	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", biz.time.End())
		return nil, core.ErrUnauthorized.WithDebug(err.Error())
	}
	logger.Info("response", "method", method, "data", claims, "ms", biz.time.End())
	return claims, nil
}
