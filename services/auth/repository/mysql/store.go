package mysql

import (
	"context"
	"demo-service/helpers"
	"demo-service/services/auth/entity"
	"github.com/pkg/errors"
	"github.com/viettranx/service-context/core"
	"gorm.io/gorm"
	"log/slog"
	"os"
)

var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

type mysqlRepo struct {
	db   *gorm.DB
	time helpers.Timer
}

func NewMySQLRepository(db *gorm.DB) *mysqlRepo {
	return &mysqlRepo{db: db}
}

func (repo *mysqlRepo) AddNewAuth(ctx context.Context, data *entity.Auth) error {
	var method = "AddNewAuth_SQL"
	repo.time.Start()
	logger.Info("request", "method", method)

	if err := repo.db.Table(data.TableName()).Create(data).Error; err != nil {
		logger.Error("response", "method", method, "err", err, "ms", repo.time.End())
		return errors.WithStack(err)
	}
	logger.Info("response", "method", method, "data", true, "ms", repo.time.End())
	return nil
}

func (repo *mysqlRepo) GetAuth(ctx context.Context, email string) (*entity.Auth, error) {
	var method = "GetAuth_SQL"
	repo.time.Start()
	logger.Info("request", "method", method)

	var data entity.Auth

	if err := repo.db.
		Table(data.TableName()).
		Where("email = ?", email).
		First(&data).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error("response", "method", method, "err", err, "ms", repo.time.End())
			return nil, core.ErrRecordNotFound
		}
		logger.Error("response", "method", method, "err", err, "ms", repo.time.End())
		return nil, errors.WithStack(err)
	}
	logger.Info("response", "method", method, "data", data, "ms", repo.time.End())
	return &data, nil
}
