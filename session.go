package auth

type SID string

type Session struct {
	ID        SID
	UserId    UID
	ExpiresAt Time
}

type SessionManager interface {
	CreateSession(token Token, user *User) (*Session, error)
	ReadSession(token Token) (*Session, error)
	UpdateSession(expiry Time) error
	DeleteSession(sid SID) error
	DeleteUserSessions(uid UID) error
}
