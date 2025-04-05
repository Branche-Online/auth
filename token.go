package auth

type Token string

type OTP struct {
	Token  Token
	UID    UID
	Expiry Time
}

type TokenMaker interface {
	GenerateToken() (Token, error)
	SignToken(token Token, secret Key) (Digest, error)
	VerifyToken(token Token, signature Digest, publicKey Key) (bool, error)
	CreateOTP(uid UID, expiry Time) (*OTP, error)
	ReadOTP(token Token) (UID, error)
	DestroyOTP(token Token) error
}
