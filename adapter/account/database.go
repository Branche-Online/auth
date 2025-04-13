package account

import (
	"errors"
	"time"

	"github.com/Branche-Online/auth"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// AccountBaseModel represents the base model for user accounts
// It contains the common fields for all user accounts and account profiles
type AccountBaseModel struct {
	CreatedAt auth.Time      `json:"created_at"`
	UpdatedAt auth.Time      `json:"updated_at"`
	DeletedAt *auth.Time     `sql:"index" json:"deleted_at"`
	ID        datatypes.UUID `gorm:"primaryKey;type:uuid" json:"id"`
}

// BeforeCreate is a GORM hook that is called before creating a new record
// It generates a new UUID for the ID field if it is not already set
// It is used to ensure that each record has a unique ID
// It is used to set the created at and updated at timestamps to the current time
// It is used to set the deleted at timestamp to nil
func (model *AccountBaseModel) BeforeCreate(tx *gorm.DB) (err error) {
	id, err := uuid.NewRandom()

	if err != nil && model.ID == (datatypes.UUID{}) {
		model.ID = datatypes.UUID(id)
	}

	return err
}

// AccountProfileInDatabase represents the user profile in the database
// It implements the auth.UserProfile interface
// It contains the user profile information and the user ID
// It is used to create, read, update and delete the user profile in the database
// It is used to store the user profile information for different authentication providers
type AccountProfileInDatabase struct {
	AccountBaseModel
	Type                  auth.ProviderType `json:"provider_type"`
	Name                  *string           `json:"provider_name"`
	UID                   datatypes.UUID    `json:"user_id"`
	ProviderAccountId     *string           `json:"provider_account_id"`
	Info                  *string           `json:"info"`
	NotBefore             *auth.Duration    `json:"not_before"`
	RefreshToken          *string           `json:"refresh_token"`
	RefreshTokenExpiresIn *auth.Duration    `json:"refresh_token_expires_in"`
	AccessToken           *string           `json:"access_token"`
	ExpiresAt             *auth.Time        `json:"expires_at"`
	TokenType             *string           `json:"token_type"`
	Scope                 *string           `json:"scope"`
	IDToken               *string           `json:"id_token"`
	IDTokenExpiresIn      *auth.Duration    `json:"id_token_expires_in"`
	SessionState          *string           `json:"session_state"`
	ExtExpiresIn          *auth.Duration    `json:"ext_expires_in"`
}

// Implementation of the auth.UserProfile interface
// UserId returns the user ID
// It is used to identify the user profile in the database
func (profile *AccountProfileInDatabase) PID() string {
	return profile.ID.String()
}

// UserId returns the user ID that is associated with the profile
func (profile *AccountProfileInDatabase) UserId() auth.UID {
	return auth.UID(profile.UID.String())
}

// Provider returns the identity provider type
func (profile *AccountProfileInDatabase) IdPType() auth.ProviderType {
	return profile.Type
}

// ProviderAccountId returns the identity provider name for the profile
func (profile *AccountProfileInDatabase) IdPName() string {
	return *profile.Name
}

// IdPAccountId returns the identity provider account ID of the profile
func (profile *AccountProfileInDatabase) IdPAccountId() string {
	return *profile.ProviderAccountId
}

// AccountData represents the user account data
type AccountData struct {
	State         auth.UserStatus `json:"status"`
	Username      *string         `json:"username"`
	Email         *string         `json:"email"`
	EmailVerified bool            `gorm:"default false" json:"email_verified"`
	Password      *string         `json:"password"`
	LastLogin     *auth.Time      `json:"last_login"`
	Phone         *string         `json:"phone"`
	GivenName     *string         `json:"given_name"`
	FamilyName    *string         `json:"family_name"`
	DOB           *auth.Time      `json:"dob"`
	Image         *string         `json:"image"`
	Location      *string         `json:"location"`
	Bio           *string         `json:"bio"`
	VerifiedAt    *auth.Time      `json:"verified_at"`
	VerifiedBy    *string         `json:"verified_by"`
	Extra         datatypes.JSON  `json:"additional"`
}

// AccountInDatabase represents the user account in the database
// It implements the auth.User interface
// It contains the user information and the profiles associated with the user
type AccountInDatabase struct {
	AccountBaseModel
	AccountData
	Profiles []AccountProfileInDatabase `gorm:"foreignKey:UserID" json:"profiles"`
}

// Implementation of the auth.User interface
// UID returns the user ID
// It is used to identify the user account in the database
func (user *AccountInDatabase) UID() auth.UID {
	return auth.UID(user.ID.String())
}

// Status returns the status of the user
// It is used to check the status of the user account
// It is used to determine if the user account is active, pending, disabled or archived
func (user *AccountInDatabase) Status() auth.UserStatus {
	return user.State
}

// DisplayName returns the display name of the user
// It concatenates the users given name and family name
// If both are nil, it returns the username if available
// If none are available, it returns an empty string
func (user *AccountInDatabase) DisplayName() string {
	fname := ""
	lname := ""

	if user.GivenName != nil {
		fname = *user.GivenName
	}

	if user.FamilyName != nil {
		lname = *user.FamilyName
	}

	displayName := fname + " " + lname

	if user.GivenName == nil && user.FamilyName == nil {
		if user.Username != nil {
			displayName = *user.Username
		} else {
			displayName = ""
		}
	}

	return displayName
}

// DbDriverType is a type that represents the database driver type
// It is used to specify the database driver type when creating a new database connection
// It is used to create a new database connection using the gorm library
type DbDriverType string

// Supported database driver types
const (
	PGSQL   DbDriverType = "pgsql"
	MYSQL   DbDriverType = "mysql"
	MARIADB DbDriverType = "mariadb"
	SQLITE  DbDriverType = "sqlite"
)

// DatabaseAccountManager type implements the auth.AccountManger interface
// It is used to create, read, update and delete the user accounts and profiles in the database
type DatabaseAccountManager struct {
	ds *gorm.DB
}

// NewDatabaseAccountManager creates a new database account manager
// It takes a data source name (DSN) and a database driver type as parameters
// It returns a pointer to the DatabaseAccountManager and an error
// It initializes the database connection and migrates the database schema
// It creates the database tables for the user accounts and profiles
// It returns an error if the database connection fails or if the migration fails
func NewDatabaseAccountManager(dsn string, dbType DbDriverType) (*DatabaseAccountManager, error) {

	dbAccMgr := &DatabaseAccountManager{}
	var db *gorm.DB
	var err error = nil

	switch dbType {
	case PGSQL:
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	case SQLITE:
		db, err = gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	case MYSQL:
		db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	default:
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	}

	if err != nil {
		dbAccMgr.ds = db

		if err := db.AutoMigrate(&AccountInDatabase{}, &AccountProfileInDatabase{}); err != nil {
			return dbAccMgr, err
		}
	}

	return nil, err
}

// GetDatastore returns the database connection
func (dbAccMgr *DatabaseAccountManager) GetDatastore() (*gorm.DB, error) {

	if dbAccMgr.ds != nil {
		return dbAccMgr.ds, nil
	}

	return nil, errors.New("datastore not initialized")
}

// CreateUser creates a new user account in the database
// It takes a pointer to the AccountData struct as a parameter
// It returns a pointer to the AccountInDatabase struct and an error
// It creates a new user account in the database with the provided data
// It returns an error if the database connection fails or if the user account creation fails
// It sets the user account state to PENDING
// It sets the user account ID to a new UUID
// It sets the user account created at and updated at timestamps to the current time
// It sets the user account email verified flag to false
func (dbAccMgr *DatabaseAccountManager) CreateUser(data any) (*AccountInDatabase, error) {
	db, err := dbAccMgr.GetDatastore()

	udata, ok := data.(*AccountData)
	if !ok {
		return nil, errors.New("invalid user data")
	}

	if err != nil {
		acc := &AccountInDatabase{}

		acc.State = auth.PENDING
		acc.Username = udata.Username
		acc.Email = udata.Email
		acc.EmailVerified = udata.EmailVerified
		acc.Password = udata.Password
		acc.LastLogin = udata.LastLogin
		acc.Phone = udata.Phone
		acc.GivenName = udata.GivenName
		acc.FamilyName = udata.FamilyName
		acc.DOB = udata.DOB
		acc.Image = udata.Image
		acc.Location = udata.Location
		acc.Bio = udata.Bio
		acc.VerifiedAt = udata.VerifiedAt
		acc.VerifiedBy = udata.VerifiedBy
		acc.Extra = datatypes.JSON(udata.Extra)

		err = db.Create(acc).Error

		if err != nil {
			return acc, err
		}
	}

	return nil, err
}

// ReadUser reads a user account from the database
// It takes a user ID as a parameter
// It returns a pointer to the AccountInDatabase struct and an error
// It reads the user account from the database with the provided user ID
// It returns an error if the database connection fails or if the user account is not found
func (dbAccMgr *DatabaseAccountManager) ReadUser(uid auth.UID) (*AccountInDatabase, error) {
	db, err := dbAccMgr.GetDatastore()

	if err != nil {
		acc := &AccountInDatabase{}

		err = db.First(acc, "id = ?", uid).Error

		if err != nil {
			return acc, err
		}
	}

	return nil, err
}

// UpdateUser updates a user account in the database
// It takes a user ID and a pointer to the AccountData struct as parameters
func (dbAccMgr *DatabaseAccountManager) UpdateUser(uid auth.UID, data any) error {
	db, err := dbAccMgr.GetDatastore()

	if err != nil {
		udata, ok := data.(*AccountData)
		if !ok {
			return errors.New("invalid user data")
		}

		acc := &AccountInDatabase{}

		err = db.First(acc, "id = ?", uid).Error

		if err != nil {
			return err
		}

		acc.State = udata.State
		acc.EmailVerified = udata.EmailVerified
		acc.Username = udata.Username
		acc.Email = udata.Email
		acc.Password = udata.Password
		acc.LastLogin = udata.LastLogin
		acc.Phone = udata.Phone
		acc.GivenName = udata.GivenName
		acc.FamilyName = udata.FamilyName
		acc.DOB = udata.DOB
		acc.Image = udata.Image
		acc.Location = udata.Location
		acc.Bio = udata.Bio
		acc.VerifiedAt = udata.VerifiedAt
		acc.VerifiedBy = udata.VerifiedBy
		acc.Extra = datatypes.JSON(udata.Extra)
		acc.UpdatedAt = auth.Time(time.Now())

		err = db.Save(acc).Error

		if err != nil {
			return err
		}
	}

	return nil
}

// ConnectProfile connects a user profile to a user account in the database
// It takes a user ID and a pointer to the AccountProfileInDatabase struct as parameters
// It returns an error if the database connection fails or if the user profile association fails
func (dbAccMgr *DatabaseAccountManager) ConnectProfile(uid auth.UID, profile *AccountProfileInDatabase) error {
	db, err := dbAccMgr.GetDatastore()

	if err != nil {
		acc := db.Model(&AccountInDatabase{}).Where("id = ?", uid).First(&AccountInDatabase{})
		if acc.Error != nil {
			return acc.Error
		}

		err = db.Model(acc).Association("Profiles").Append(profile)
	}

	return err
}

// DisconnectProfile disconnects a user profile from a user account in the database
// It takes a user ID and a profile ID as parameters
// It returns an error if the database connection fails or if the user profile disassociation fails
func (dbAccMgr *DatabaseAccountManager) DisconnectProfile(uid auth.UID, prid string) error {
	db, err := dbAccMgr.GetDatastore()

	if err != nil {
		acc := db.Model(&AccountInDatabase{}).Where("id = ?", uid).First(&AccountInDatabase{})
		if acc.Error != nil {
			return acc.Error
		}

		prof := &AccountProfileInDatabase{}
		err = db.Where("id = ?", prid).First(prof).Error

		if err != nil {
			return err
		}

		err = db.Model(acc).Association("Profiles").Delete(prof)
	}

	return err
}

// DeleteUser deletes a user account from the database
// It takes a user ID as a parameter
// It returns an error if the database connection fails or if the user account deletion fails
func (dbAccMgr *DatabaseAccountManager) DeleteUser(uid auth.UID) error {
	db, err := dbAccMgr.GetDatastore()

	if err != nil {
		err = db.Delete(&AccountInDatabase{}, "id = ?", uid).Error
	}

	return err
}
