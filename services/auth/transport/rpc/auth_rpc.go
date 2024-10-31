package rpc

import (
	"context"
	"demo-service/helpers"
	"demo-service/proto/pb"
	"github.com/golang-jwt/jwt/v5"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	"log/slog"
	"os"
)

var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

type Business interface {
	IntrospectToken(ctx context.Context, accessToken string) (*jwt.RegisteredClaims, error)
	Login(ctx context.Context, password *pb.AuthEmailPassword) (*pb.TokenResponse, error)
	Register(ctx context.Context, register *pb.AuthRegister) (*empty.Empty, error)
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
