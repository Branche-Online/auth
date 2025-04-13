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
	UID() UID
	Status() UserStatus
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
	PID() string
	UserId() UID
	IdPType() ProviderType
	IdPName() string
	IdPAccountId() string
}

type AccountManager interface {
	CreateUser(data any) (*User, error)
	ReadUser(uid UID) (*User, error)
	UpdateUser(uid UID, data any) error
	ConnectProfile(uid UID, profile *UserProfile) error
	DisconnectProfile(uid UID, prid string) error
	DeleteUser(uid UID) error
}
