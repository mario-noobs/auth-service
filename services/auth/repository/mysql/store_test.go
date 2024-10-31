package mysql

import (
	"context"
	"demo-service/helpers"
	"demo-service/services/auth/entity"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/viettranx/service-context/core"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"testing"
)

func TestAddNewAuth_Success(t *testing.T) {
	// Arrange
	time2 := new(helpers.Timer)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %s", err)
	}

	defer db.Close()

	gormDB, err := gorm.Open(mysql.New(mysql.Config{Conn: db,
		SkipInitializeWithVersion: true}), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open gorm: %s", err)
	}

	repo := &mysqlRepo{
		db:   gormDB,
		time: *time2,
	}

	authData := &entity.Auth{
		UserId:     1,
		AuthType:   "email",
		Email:      "test@example.com",
		Salt:       "random_salt",
		Password:   "hashed_password",
		FacebookId: "",
	}

	// Expectation for AddNewAuth
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO(.*)").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), authData.UserId, authData.AuthType, authData.Email, authData.Salt, authData.Password, authData.FacebookId).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Act
	err = repo.AddNewAuth(context.Background(), authData)

	// Assert
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetAuth_Success(t *testing.T) {
	// Arrange
	time := new(helpers.Timer)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %s", err)
	}
	defer db.Close()

	gormDB, err := gorm.Open(mysql.New(mysql.Config{Conn: db,
		SkipInitializeWithVersion: true}), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open gorm: %s", err)
	}

	repo := &mysqlRepo{
		db:   gormDB,
		time: *time,
	}

	expectedAuth := &entity.Auth{Email: "test@example.com", Password: "password"}

	// Set expectation for SELECT VERSION()
	//mock.ExpectQuery("SELECT VERSION()").WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow("5.7.30"))

	// Updated expectation for GetAuth
	mock.ExpectQuery("SELECT(.*)").
		WithArgs(expectedAuth.Email).
		WillReturnRows(sqlmock.NewRows([]string{"email", "password"}).AddRow(expectedAuth.Email, expectedAuth.Password))

	// Act
	result, err := repo.GetAuth(context.Background(), expectedAuth.Email)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, expectedAuth.Email, result.Email)
	assert.Equal(t, expectedAuth.Password, result.Password)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetAuth_NotFound(t *testing.T) {
	// Arrange
	time := new(helpers.Timer)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %s", err)
	}
	defer db.Close()

	gormDB, err := gorm.Open(mysql.New(mysql.Config{Conn: db,
		SkipInitializeWithVersion: true}), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open gorm: %s", err)
	}

	repo := &mysqlRepo{
		db:   gormDB,
		time: *time,
	}

	email := "notfound@example.com"

	// Expectation
	mock.ExpectQuery("SELECT(.*)").
		WithArgs(email).
		WillReturnError(gorm.ErrRecordNotFound)

	// Act
	result, err := repo.GetAuth(context.Background(), email)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, core.ErrRecordNotFound, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}
