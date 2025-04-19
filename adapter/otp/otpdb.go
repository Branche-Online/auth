package otp

import (
	"errors"
	"time"

	"github.com/branche-online/auth"
	"github.com/branche-online/auth/adapter/account"
	"github.com/branche-online/auth/adapter/database"
	"github.com/branche-online/auth/adapter/token"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// OTPInDatabase is the struct that represents the OTP in the database
type OTPInDatabase struct {
	CreatedAt auth.Time                  `json:"created_at"`
	Token     auth.Token                 `gorm:"primaryKey;autoincrement:false" json:"token"`
	UID       auth.UID                   `gorm:"primaryKey;autoincrement:false" json:"uid"`
	TTL       auth.Duration              `json:"ttl"`
	User      *account.AccountInDatabase `gorm:"foreignKey:uid" json:"user"`
}

// TableName overrides the default table name used by the ORM. It maps OTPs to `otps` table
// It is used to specify the table name to store the otps in the database
func (OTPInDatabase) TableName() string {
	return "otps"
}

// OTPDbManager is the struct that represents the OTP manager
// It is used to manage the OTPs in the database
// It implements the OTPManager interface
// It is used to create, read and destroy OTPs in the database
type OTPDbManager struct {
	ds     *gorm.DB
	gen    *token.StandardTokenManager
	tkopts *token.TokenGeneratorOptions
}

// NewOTPDbManager is a constructor for OTPDbManager and returns new OTPDbManager.
// It takes a dsn (data source name), a database driver type, GORM database configuration options,
// Token Generator options, and a StandardTokenManager as input
// It returns a new OTP manager and an error if the database connection fails
// It uses the gorm library to connect to the database
// It uses the gorm library to perform automigration of the database schema
func NewOTPDbManager(dsn string, dbType database.DbDriverType, cfg *gorm.Config, tkopts *token.TokenGeneratorOptions, tkgn *token.StandardTokenManager) (*OTPDbManager, error) {
	otpMgr := &OTPDbManager{}
	var db *gorm.DB
	var err error = nil
	var config = &gorm.Config{}
	if cfg != nil {
		config = cfg
	}

	// Set the token generator
	// It is used to generate the token for the OTP
	if tkgn == nil {
		return nil, errors.New("token generator not initialized")
	}
	otpMgr.gen = tkgn

	if tkopts == nil {
		tkopts = &token.TokenGeneratorOptions{
			Algorithm: token.RANDB10,
			Length:    6,
			Alphabet:  nil,
		}
	}
	otpMgr.tkopts = tkopts

	switch dbType {
	case database.PGSQL:
		db, err = gorm.Open(postgres.Open(dsn), config)
	case database.SQLITE:
		db, err = gorm.Open(sqlite.Open(dsn), config)
	case database.MYSQL:
		db, err = gorm.Open(mysql.Open(dsn), config)
	case database.MARIADB:
		db, err = gorm.Open(mysql.Open(dsn), config)
	default:
		db, err = gorm.Open(postgres.Open(dsn), config)
	}

	if err != nil {
		otpMgr.ds = db

		if err := db.AutoMigrate(&OTPInDatabase{}, &account.AccountInDatabase{}); err != nil {
			return otpMgr, err
		}
	}

	return nil, err
}

// SetDatastore sets the database connection for the otp manager
// It will perform an automigration of the database schema
// It returns an error if the database connection is nil
func (otpMgr *OTPDbManager) SetDatastore(db *gorm.DB) error {

	if db == nil {
		return errors.New("datastore not initialized")
	}

	otpMgr.ds = db

	return db.AutoMigrate(&OTPInDatabase{}, &account.AccountInDatabase{})
}

// GetDatastore returns the database connection
// It returns the database connection used by the otp manager to perform database operations
// It returns an error if the database connection is nil
func (otpMgr *OTPDbManager) GetDatastore() (*gorm.DB, error) {

	if otpMgr.ds != nil {
		return otpMgr.ds, nil
	}

	return nil, errors.New("datastore not initialized")
}

// GetTokenGenerator returns the token generator
// It returns the token generator used by the otp manager to generate tokens for the OTPs
// It returns an error if the token generator is nil
func (otpMgr *OTPDbManager) GetTokenGenerator() (*token.StandardTokenManager, error) {
	if otpMgr.gen != nil {
		return otpMgr.gen, nil
	}
	return nil, errors.New("token generator not initialized")
}

// CreateOTP creates a new OTP in the database
// It takes a user id and a time to live (TTL) as input
// It generates a new token using the token generator
// It returns the OTP object and an error if the database operation fails
// It returns the OTP object if the database operation is successful
func (otpMgr *OTPDbManager) CreateOTP(uid auth.UID, ttl auth.Duration) (*auth.OTP, error) {
	db, err := otpMgr.GetDatastore()
	if err != nil {
		return nil, err
	}

	var tkgn *token.StandardTokenManager
	tkgn, err = otpMgr.GetTokenGenerator()

	if err != nil {
		otp := &OTPInDatabase{}
		var tk auth.Token
		tk, err = tkgn.GenerateToken(otpMgr.tkopts)
		if err != nil {
			otp.Token = tk
		} else {
			return nil, err
		}
		otp.UID = uid
		otp.CreatedAt = auth.Time(time.Now())
		otp.TTL = ttl

		result := db.Create(otp)

		if result.Error == nil {
			return &auth.OTP{
				CreatedAt: otp.CreatedAt,
				Token:     otp.Token,
				UID:       otp.UID,
				TTL:       otp.TTL,
			}, nil
		}

		err = result.Error
	}

	return nil, err
}

// ReadOTP reads an OTP from the database
// It takes a token and a user id as input
// It returns nil and an error if the database operation fails
// It returns the OTP object if the database operation is successful
func (otpMgr *OTPDbManager) ReadOTP(token auth.Token, uid auth.UID) (*auth.OTP, error) {
	db, err := otpMgr.GetDatastore()

	if err != nil {
		return nil, err
	}

	var otp OTPInDatabase
	result := db.Where("token = ? AND uid = ?", token, uid).First(&otp)

	if result.Error == nil {
		return &auth.OTP{
			CreatedAt: otp.CreatedAt,
			Token:     otp.Token,
			UID:       otp.UID,
			TTL:       otp.TTL,
		}, nil
	}

	return nil, result.Error
}

// DestroyOTP destroys an OTP in the database
// It takes a token and a user id as input
// It deletes the OTP from the database
// It returns an error if the database operation fails
// It returns nil if the database operation is successful
func (otpMgr *OTPDbManager) DestroyOTP(token auth.Token, uid auth.UID) error {
	db, err := otpMgr.GetDatastore()

	if err != nil {
		return err
	}

	var otp OTPInDatabase
	result := db.Where("token = ? AND uid = ?", token, uid).Delete(&otp)

	if result.Error == nil {
		return nil
	}

	return result.Error
}
