package auth

type SID string

type Session struct {
	CreatedAt Time     `json:"created_at"`
	UpdatedAt Time     `json:"updated_at"`
	ID        SID      `json:"id"`
	UserId    UID      `json:"user_id"`
	TTL       Duration `json:"ttl"`
}

type SessionManager interface {
	CreateSession(token Token, user *User) (*Session, error)
	ReadSession(token Token) (*Session, error)
	UpdateSession(expiry Duration) error
	DeleteSession(sid SID) error
	DeleteUserSessions(uid UID) error
}
