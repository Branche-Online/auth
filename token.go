package auth

type Token string

type OTP struct {
	Token  Token
	UID    UID
	Expiry Time
}
type TokenMaker interface {
	GenerateToken() (Token, error)
	CreateOTP(uid UID, expiry Time) error
	ReadOTP(token Token) (UID, error)
}
