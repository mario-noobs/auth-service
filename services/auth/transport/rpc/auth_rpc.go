package rpc

import (
	"context"
	"demo-service/helpers"
	"demo-service/proto/pb"
	"log/slog"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
)

var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

type Business interface {
	IntrospectToken(ctx context.Context, accessToken string) (*jwt.RegisteredClaims, error)
	Login(ctx context.Context, password *pb.AuthEmailPassword) (*pb.TokenResponse, error)
	Register(ctx context.Context, register *pb.AuthRegister) (*empty.Empty, error)
	Logout(ctx context.Context, accessToken string) (*empty.Empty, error)
	RefreshToken(ctx context.Context, refreshToken string) (*pb.TokenResponse, error)
}

type grpcService struct {
	business Business
	time     helpers.Timer
}

func (s *grpcService) Login(ctx context.Context, password *pb.AuthEmailPassword) (*pb.TokenResponse, error) {
	var method = "Login"
	s.time.Start()
	logger.Info("request", "method", method)
	response, err := s.business.Login(ctx, password)
	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", s.time.End())
		return nil, errors.WithStack(err)
	}
	logger.Info("response", "method", method, "data", response, "ms", s.time.End())
	return response, nil
}

func (s *grpcService) Register(ctx context.Context, register *pb.AuthRegister) (*empty.Empty, error) {
	var method = "Register"
	s.time.Start()
	logger.Info("request", "method", method)
	result, err := s.business.Register(ctx, register)
	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", s.time.End())
		return nil, errors.WithStack(err)
	}
	logger.Info("response", "method", method, "data", true, "ms", s.time.End())
	return result, nil
}

func NewService(business Business) *grpcService {
	return &grpcService{business: business}
}

func (s *grpcService) IntrospectToken(ctx context.Context, req *pb.IntrospectReq) (*pb.IntrospectResp, error) {

	var method = "IntrospectToken"
	s.time.Start()
	logger.Info("request", "method", method)

	claims, err := s.business.IntrospectToken(ctx, req.AccessToken)

	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", s.time.End())
		return nil, errors.WithStack(err)
	}
	logger.Info("response", "method", method, "data", claims, "ms", s.time.End())
	return &pb.IntrospectResp{
		Tid: claims.ID,
		Sub: claims.Subject,
	}, nil
}

func (s *grpcService) Logout(ctx context.Context, req *pb.LogoutRequest) (*empty.Empty, error) {
	var method = "Logout"
	s.time.Start()
	logger.Info("request", "method", method)

	result, err := s.business.Logout(ctx, req.AccessToken)
	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", s.time.End())
		return nil, errors.WithStack(err)
	}

	logger.Info("response", "method", method, "data", "logout successful", "ms", s.time.End())
	return result, nil
}

func (s *grpcService) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.TokenResponse, error) {
	var method = "RefreshToken"
	s.time.Start()
	logger.Info("request", "method", method)

	response, err := s.business.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", s.time.End())
		return nil, errors.WithStack(err)
	}

	logger.Info("response", "method", method, "data", "tokens refreshed", "ms", s.time.End())
	return response, nil
}
