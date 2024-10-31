package rpc

import (
	"context"
	"demo-service/helpers"
	"demo-service/proto/pb"
	"demo-service/services/mockClient"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateUser_Success(t *testing.T) {
	// Arrange
	mockClient := new(mockClient.MockClient)
	time := new(helpers.Timer)
	rpcClient := &rpcClient{
		client: mockClient,
		time:   *time,
	}
	ctx := context.Background()
	firstName := "John"
	lastName := "Doe"
	email := "john.doe@example.com"
	expectedID := 1

	// Mock the CreateUser response
	mockClient.On("CreateUser", ctx, &pb.CreateUserReq{
		FirstName: firstName,
		LastName:  lastName,
		Email:     email,
	}).Return(&pb.NewUserIdResp{Id: int32(expectedID)}, nil)

	// Act
	newID, err := rpcClient.CreateUser(ctx, firstName, lastName, email)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, expectedID, newID)
	mockClient.AssertExpectations(t)
}

func TestCreateUser_Error(t *testing.T) {
	// Arrange
	mockClient := new(mockClient.MockClient)
	time := new(helpers.Timer)
	rpcClient := &rpcClient{
		client: mockClient,
		time:   *time,
	}
	ctx := context.Background()
	firstName := "Jane"
	lastName := "Doe"
	email := "jane.doe@example.com"
	expectedErr := errors.New("user creation failed")

	// Mock the CreateUser error response
	mockClient.On("CreateUser", ctx, &pb.CreateUserReq{
		FirstName: firstName,
		LastName:  lastName,
		Email:     email,
	}).Return(&pb.NewUserIdResp{}, expectedErr)

	// Act
	_, err := rpcClient.CreateUser(ctx, firstName, lastName, email)

	// Assert
	assert.Error(t, err)
	//assert.Equal(t, 0, newID)
	mockClient.AssertExpectations(t)
}
