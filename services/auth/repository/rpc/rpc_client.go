package rpc

import (
	"context"
	"demo-service/helpers"
	"demo-service/proto/pb"
	"github.com/pkg/errors"
	"log/slog"
	"os"
)

var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

type rpcClient struct {
	client pb.UserServiceClient
	time   helpers.Timer
}

func NewClient(client pb.UserServiceClient) *rpcClient {
	return &rpcClient{client: client}
}

func (c *rpcClient) CreateUser(ctx context.Context, firstName, lastName, email string) (newId int, err error) {
	var method = "CreateUser_SQL"
	c.time.Start()
	logger.Info("request", "method", method)

	resp, err := c.client.CreateUser(ctx, &pb.CreateUserReq{
		FirstName: firstName,
		LastName:  lastName,
		Email:     email,
	})

	if err != nil {
		logger.Error("response", "method", method, "err", err, "ms", c.time.End())
		return 0, errors.WithStack(err)
	}

	logger.Info("response", "method", method, "data", resp, "ms", c.time.End())
	return int(resp.Id), nil
}
