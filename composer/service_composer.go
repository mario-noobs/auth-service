package composer

import (
	"demo-service/common"
	"demo-service/proto/pb"
	authBusiness "demo-service/services/auth/business"
	authSQLRepository "demo-service/services/auth/repository/mysql"
	userClient "demo-service/services/auth/repository/rpc"
	authRPC "demo-service/services/auth/transport/rpc"
	"github.com/gin-gonic/gin"
	sctx "github.com/viettranx/service-context"
)

type AuthService interface {
	LoginHdl() func(*gin.Context)
	RegisterHdl() func(*gin.Context)
}

//func ComposeAuthAPIService(serviceCtx sctx.ServiceContext) AuthService {
//	db := serviceCtx.MustGet(common.KeyCompMySQL).(common.GormComponent)
//	jwtComp := serviceCtx.MustGet(common.KeyCompJWT).(common.JWTProvider)
//
//	authRepo := authSQLRepository.NewMySQLRepository(db.GetDB())
//	hasher := new(common.Hasher)
//
//	userClient := authUserRPC.NewClient(ComposeUserRPCClient(serviceCtx))
//	biz := authBusiness.NewBusiness(authRepo, userClient, jwtComp, hasher)
//	serviceAPI := authAPI.NewAPI(serviceCtx, biz)
//
//	return serviceAPI
//}

func ComposeAuthGRPCService(serviceCtx sctx.ServiceContext) pb.AuthServiceServer {
	db := serviceCtx.MustGet(common.KeyCompMySQL).(common.GormComponent)
	jwtComp := serviceCtx.MustGet(common.KeyCompJWT).(common.JWTProvider)

	authRepo := authSQLRepository.NewMySQLRepository(db.GetDB())
	hasher := new(common.Hasher)

	// In Auth GRPC service, user repository is unnecessary
	biz := authBusiness.NewBusiness(authRepo, nil, jwtComp, hasher)
	authService := authRPC.NewService(biz)

	return authService
}

func ComposeUserAuthGRPCService(serviceCtx sctx.ServiceContext) pb.UserAuthServiceServer {
	db := serviceCtx.MustGet(common.KeyCompMySQL).(common.GormComponent)
	jwtComp := serviceCtx.MustGet(common.KeyCompJWT).(common.JWTProvider)

	authRepo := authSQLRepository.NewMySQLRepository(db.GetDB())
	userRepo := userClient.NewClient(ComposeUserRPCClient(serviceCtx))
	hasher := new(common.Hasher)

	// In Auth GRPC service, user repository is unnecessary
	biz := authBusiness.NewBusiness(authRepo, userRepo, jwtComp, hasher)
	authService := authRPC.NewService(biz)

	return authService
}
