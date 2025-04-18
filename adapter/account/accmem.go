package account

import (
	"errors"
	"time"

	"github.com/branche-online/auth"
)

// AccountInMemoryBaseModel represents the base model for user accounts
// It contains the common fields for all user accounts and account profiles
type AccountInMemoryBaseModel struct {
	CreatedAt auth.Time `json:"created_at"`
	UpdatedAt auth.Time `json:"updated_at"`
	ID        auth.UID  `json:"id"`
}

// AccountProfileInMemory represents the user profile in memory
// It implements the auth.UserProfile interface
// It contains the user profile information and the user ID
// It is used to create, read, update and delete the user profile in memory
// It is used to store the user profile information for different authentication providers
type AccountProfileInMemory struct {
	AccountInMemoryBaseModel
	Type                  auth.ProviderType `json:"provider_type"`
	Name                  *string           `json:"provider_name"`
	UID                   auth.UID          `json:"user_id"`
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
// It is used to identify the user profile in memory
func (profile *AccountProfileInMemory) PID() string {
	return string(profile.ID)
}

// UserId returns the user ID that is associated with the profile
func (profile *AccountProfileInMemory) UserId() auth.UID {
	return profile.UID
}

// Provider returns the identity provider type
func (profile *AccountProfileInMemory) IdPType() auth.ProviderType {
	return profile.Type
}

// ProviderAccountId returns the identity provider name for the profile
func (profile *AccountProfileInMemory) IdPName() string {
	return *profile.Name
}

// IdPAccountId returns the identity provider account ID of the profile
func (profile *AccountProfileInMemory) IdPAccountId() string {
	return *profile.ProviderAccountId
}

// AccountInMemoryDataModel represents the user account data
type AccountInMemoryDataModel struct {
	State         auth.UserStatus `json:"status"`
	Username      *string         `json:"username"`
	Email         *string         `json:"email"`
	EmailVerified bool            `json:"email_verified"`
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
	Extra         []any           `json:"additional"`
}

// AccountInMemory represents the user account in memory
// It implements the auth.User interface
// It contains the user information and the profiles associated with the user
type AccountInMemory struct {
	AccountInMemoryBaseModel
	AccountInMemoryDataModel
	OTPs     map[auth.Token]auth.OTP             `json:"otps"`
	Sessions map[auth.SID]auth.Session           `json:"sessions"`
	Profiles map[auth.UID]AccountProfileInMemory `json:"profiles"`
}

// Implementation of the auth.User interface
// UID returns the user ID
// It is used to identify the user account in memory
func (user *AccountInMemory) UID() auth.UID {
	return user.ID
}

// Status returns the status of the user
// It is used to check the status of the user account
// It is used to determine if the user account is active, pending, disabled or archived
func (user *AccountInMemory) Status() auth.UserStatus {
	return user.State
}

// DisplayName returns the display name of the user
// It concatenates the users given name and family name
// If both are nil, it returns the username if available
// If none are available, it returns an empty string
func (user *AccountInMemory) DisplayName() string {
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

// InMemoryAccountManager type implements the auth.AccountManger interface
// It is used to create, read, update and delete the user accounts and profiles in memory
type InMemoryAccountManager struct {
	ds map[auth.UID]AccountInMemory
}

// NewInMemoryAccountManager creates a new in memory account manager
// It returns an error if the memory account manager cannot be created
func NewInMemoryAccountManager() (*InMemoryAccountManager, error) {

	memAccMgr := &InMemoryAccountManager{}
	var err error = nil

	return memAccMgr, err
}

// CreateUser creates a new user account in memory
// It takes a pointer to the AccountDataModel struct as a parameter
// It returns a pointer to the AccountInDatabase struct and an error
// It creates a new user account in the database with the provided data
// It returns an error if the database connection fails or if the user account creation fails
// It sets the user account state to PENDING
// It sets the user account ID to a new UUID
// It sets the user account created at and updated at timestamps to the current time
// It sets the user account email verified flag to false
func (memAccMgr *InMemoryAccountManager) CreateUser(data any) (*AccountInMemory, error) {

	udata, ok := data.(*AccountInMemoryDataModel)
	if !ok {
		return nil, errors.New("invalid user data")
	}

	acc := &AccountInMemory{}

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
	acc.Extra = udata.Extra

	memAccMgr.ds[acc.ID] = *acc
	acc.CreatedAt = auth.Time(time.Now())
	acc.UpdatedAt = auth.Time(time.Now())

	return acc, nil
}

// ReadUser reads a user account from memory
// It takes a user ID as a parameter
// It returns a pointer to the AccountInMemory struct and an error
// It reads the user account from memory with the provided user ID
// It returns an error if the user account is not found
func (memAccMgr *InMemoryAccountManager) ReadUser(uid auth.UID) (*AccountInMemory, error) {

	var err error = nil
	acc, exists := memAccMgr.ds[uid]

	if !exists {
		err = errors.New("user not found")
	}

	return &acc, err
}

// UpdateUser updates a user account in memory
// It takes a user ID and a pointer to the AccountInMemory struct as parameters
func (memAccMgr *InMemoryAccountManager) UpdateUser(uid auth.UID, data any) error {
	udata, ok := data.(*AccountInMemoryDataModel)
	if !ok {
		return errors.New("invalid user data")
	}

	acc, exists := memAccMgr.ds[uid]
	if !exists {
		return errors.New("user not found")
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
	acc.Extra = udata.Extra
	acc.UpdatedAt = auth.Time(time.Now())

	return nil
}

// ConnectProfile connects a user profile to a user account in memory
// It takes a user ID and a pointer to the AccountProfileInMemory struct as parameters
// It returns an error if the user profile association fails
func (memAccMgr *InMemoryAccountManager) ConnectProfile(uid auth.UID, profile *AccountProfileInMemory) error {

	if profile == nil {
		return errors.New("invalid profile object")
	}

	if profile.UID != uid {
		return errors.New("profile and user mismatch")
	}

	acc, exists := memAccMgr.ds[uid]
	if !exists {
		return errors.New("user not found")
	}

	acc.Profiles[profile.ID] = *profile
	acc.UpdatedAt = auth.Time(time.Now())

	return nil
}

// DisconnectProfile disconnects a user profile from a user account in memory
// It takes a user ID and a profile ID as parameters
// It returns an error if the user profile disassociation fails
func (memAccMgr *InMemoryAccountManager) DisconnectProfile(uid auth.UID, prid string) error {
	acc, exists := memAccMgr.ds[uid]
	if !exists {
		return errors.New("user not found")
	}

	if _, exists := acc.Profiles[auth.UID(prid)]; !exists {
		return errors.New("profile not found")
	}

	// Delete the profile from the user's profiles map
	delete(acc.Profiles, auth.UID(prid))
	acc.UpdatedAt = auth.Time(time.Now())

	return nil
}

// ConnectSession connects a session to a user account in memory
// It takes a user ID and a pointer to the Session struct as parameters
// It returns an error if the user and session association fails
func (memAccMgr *InMemoryAccountManager) ConnectSession(uid auth.UID, ssn *auth.Session) error {

	if ssn == nil {
		return errors.New("invalid session object")
	}

	if ssn.UserId != uid {
		return errors.New("session and user mismatch")
	}

	acc, exists := memAccMgr.ds[uid]
	if !exists {
		return errors.New("user not found")
	}

	acc.Sessions[ssn.ID] = *ssn
	acc.UpdatedAt = auth.Time(time.Now())

	return nil
}

// DisconnectSession disconnects a session from a user account in memory
// It takes a user ID and a session ID as parameters
// It returns an error if the user and session disassociation fails
func (memAccMgr *InMemoryAccountManager) DisconnectSession(uid auth.UID, sid auth.SID) error {
	acc, exists := memAccMgr.ds[uid]
	if !exists {
		return errors.New("user not found")
	}

	if _, exists := acc.Sessions[sid]; !exists {
		return errors.New("session not found")
	}

	// Delete the session from the user's session map
	delete(acc.Sessions, sid)
	acc.UpdatedAt = auth.Time(time.Now())

	return nil
}

// ConnectOTP connects a otp to a user account in memory
// It takes a user ID and a pointer to the OTP struct as parameters
// It returns an error if the user and OTP association fails
func (memAccMgr *InMemoryAccountManager) ConnectOTP(uid auth.UID, otp *auth.OTP) error {

	if otp == nil {
		return errors.New("invalid otp object")
	}

	if otp.UID != uid {
		return errors.New("otp and user mismatch")
	}

	acc, exists := memAccMgr.ds[uid]
	if !exists {
		return errors.New("user not found")
	}

	acc.OTPs[otp.Token] = *otp
	acc.UpdatedAt = auth.Time(time.Now())

	return nil
}

// DisconnectOTP disconnects a otp from a user account in memory
// It takes a user ID and a otp token as parameters
// It returns an error if the user and otp disassociation fails
func (memAccMgr *InMemoryAccountManager) DisconnectOTP(uid auth.UID, tkn auth.Token) error {
	acc, exists := memAccMgr.ds[uid]
	if !exists {
		return errors.New("user not found")
	}

	if _, exists := acc.OTPs[tkn]; !exists {
		return errors.New("otp not found")
	}

	// Delete the otp from the user's otp map
	delete(acc.OTPs, tkn)
	acc.UpdatedAt = auth.Time(time.Now())

	return nil
}

// DeleteUser deletes a user account from memory
// It takes a user ID as a parameter
// It returns an error if the user account deletion fails
func (memAccMgr *InMemoryAccountManager) DeleteUser(uid auth.UID) error {
	_, exists := memAccMgr.ds[uid]
	if !exists {
		return errors.New("user not found")
	}
	// Delete the user account from the in-memory map
	delete(memAccMgr.ds, uid)

	return nil
}

// Close resets the memory account manager
func (memAccMgr *InMemoryAccountManager) Close() error {
	memAccMgr.ds = make(map[auth.UID]AccountInMemory)

	return nil
}
