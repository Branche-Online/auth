package auth

type UID string

type UserStatus int

const (
	UNKNOWN UserStatus = iota
	ACTIVE
	PENDING
	DISABLED
	ARCHIVED
)

func (status UserStatus) string() string {
	switch status {
	case ACTIVE:
		return "Active"
	case PENDING:
		return "Pending"
	case DISABLED:
		return "Disabled"
	case ARCHIVED:
		return "Archived"
	}
	return "Unknown"
}

type User interface {
	// Returns the unique identifier for the user
	UID() UID
	// Returns the state of the user object
	// This can be used to determine if the user is active, pending, disabled, or archived
	Status() UserStatus
	// Returns a display name for the user
	// This can be used to show the user in a UI
	// This can be the user's full name, first name, or any other name
	// This should be a human-readable string
	DisplayName() string
}

type ProviderType string

const (
	OIDCIDP      ProviderType = "oidc"
	SAMLIDP      ProviderType = "saml"
	LDAPIDP      ProviderType = "ldap"
	LocalCredIDP ProviderType = "local"
	OtherIDP     ProviderType = "other"
)

type UserProfile interface {
	// Returns the unique identifier for the user profile
	PID() string
	// Returns the unique identifier for the user associated with this profile
	UserId() UID
	// Returns the type of the profile provider
	IdPType() ProviderType
	// Returns the name of the profile provider
	// This can be used to determine which provider the profile is associated with
	IdPName() string
	// Returns the unique identifier for the user at the profile provider
	IdPAccountId() string
}

type AccountManager interface {
	// Takes a parameter of any data shape and returns a pointer to a user object
	CreateUser(data any) (*User, error)
	// Takes a user id and retrieves the associated user object
	ReadUser(uid UID) (*User, error)
	// Takes a user id and a data object of any shape and updates the corresponding user object
	UpdateUser(uid UID, data any) error
	// Creates an association between a user and a profile
	ConnectProfile(uid UID, profile *UserProfile) error
	// Removes the association between a user and a profile
	DisconnectProfile(uid UID, prid string) error
	// Creates an association between a user and a session
	ConnectSession(uid UID, ssn *Session) error
	// Removes the association between a user and a session
	DisconnectSession(uid UID, sid SID) error
	// Creates an association between a user and a OTP
	ConnectOTP(uid UID, otp *OTP) error
	// Removes the association between a user and a OTP
	DisconnectOTP(uid UID, tkn Token) error
	// Deletes the user object identified by the given user id
	// This should also delete all associated profiles
	DeleteUser(uid UID) error
	// Called to release any resources held by the account manager
	// This should be called when the application is shutting down
	// or when the account manager is no longer needed
	// It should not be called in the middle of a transaction
	// It should not be called if the account manager is being used
	Close() error
}
