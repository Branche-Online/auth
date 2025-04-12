package account

import (
	"github.com/Branche-Online/auth"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type AccountBaseModel struct {
	CreatedAt auth.Time      `json:"created_at"`
	UpdatedAt auth.Time      `json:"updated_at"`
	DeletedAt *auth.Time     `sql:"index" json:"deleted_at"`
	ID        datatypes.UUID `gorm:"primaryKey;type:uuid" json:"id"`
}

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

func (profile *AccountProfileInDatabase) PID() string {
	return profile.ID.String()
}

func (profile *AccountProfileInDatabase) UserId() auth.UID {
	return auth.UID(profile.UID.String())
}

func (profile *AccountProfileInDatabase) IdPType() auth.ProviderType {
	return profile.Type
}

func (profile *AccountProfileInDatabase) IdPName() string {
	return *profile.Name
}

func (profile *AccountProfileInDatabase) IdPAccountId() string {
	return *profile.ProviderAccountId
}

// AccountInDatabase represents the user account in the database
// It implements the auth.User interface
// It contains the user information and the profiles associated with the user
// It is used to create, read, update and delete the user account in the database
type AccountInDatabase struct {
	AccountBaseModel
	State         auth.UserStatus            `json:"status"`
	Username      *string                    `json:"username"`
	Email         *string                    `json:"email"`
	EmailVerified bool                       `gorm:"default false" json:"email_verified"`
	Password      *string                    `json:"password"`
	LastLogin     *auth.Time                 `json:"last_login"`
	Phone         *string                    `json:"phone"`
	GivenName     *string                    `json:"given_name"`
	FamilyName    *string                    `json:"family_name"`
	DOB           *auth.Time                 `json:"dob"`
	Image         *string                    `json:"image"`
	Location      *string                    `json:"location"`
	Bio           *string                    `json:"bio"`
	VerifiedAt    *auth.Time                 `json:"verified_at"`
	VerifiedBy    *string                    `json:"verified_by"`
	Additional    datatypes.JSON             `json:"additional"`
	Profiles      []AccountProfileInDatabase `gorm:"foreignKey:UserID" json:"profiles"`
}

// Implementation of the auth.User interface

func (user *AccountInDatabase) UID() auth.UID {
	return auth.UID(user.ID.String())
}

func (user *AccountInDatabase) Status() auth.UserStatus {
	return user.State
}

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
