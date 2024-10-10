package rpc

import (
	"context"
	"demo-service/proto/pb"
	"github.com/golang-jwt/jwt/v5"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
)

type Business interface {
	IntrospectToken(ctx context.Context, accessToken string) (*jwt.RegisteredClaims, error)
	Login(ctx context.Context, password *pb.AuthEmailPassword) (*pb.TokenResponse, error)
	Register(ctx context.Context, register *pb.AuthRegister) (*empty.Empty, error)
}

type grpcService struct {
	business Business
}

func (s *grpcService) Login(ctx context.Context, password *pb.AuthEmailPassword) (*pb.TokenResponse, error) {
	response, err := s.business.Login(ctx, password)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return response, nil
}

func (s *grpcService) Register(ctx context.Context, register *pb.AuthRegister) (*empty.Empty, error) {
	result, err := s.business.Register(ctx, register)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return result, nil
}

func NewService(business Business) *grpcService {
	return &grpcService{business: business}
}

func (s *grpcService) IntrospectToken(ctx context.Context, req *pb.IntrospectReq) (*pb.IntrospectResp, error) {
	claims, err := s.business.IntrospectToken(ctx, req.AccessToken)

	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &pb.IntrospectResp{
		Tid: claims.ID,
		Sub: claims.Subject,
	}, nil
}
