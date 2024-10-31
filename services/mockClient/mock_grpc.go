package mockClient

import (
	"context"
	"demo-service/proto/pb"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

// MockClient is a mockClient of the gRPC client.
type MockClient struct {
	mock.Mock
}

func (m *MockClient) GetUserById(ctx context.Context, in *pb.GetUserByIdReq, opts ...grpc.CallOption) (*pb.PublicUserInfoResp, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockClient) GetUsersByIds(ctx context.Context, in *pb.GetUsersByIdsReq, opts ...grpc.CallOption) (*pb.PublicUsersInfoResp, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockClient) CreateUser(ctx context.Context, in *pb.CreateUserReq, opts ...grpc.CallOption) (*pb.NewUserIdResp, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*pb.NewUserIdResp), args.Error(1)
}
