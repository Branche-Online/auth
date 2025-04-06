package auth

type OTP struct {
	Token  Token
	UID    UID
	Expiry Time
}

type OTPManager interface {
	CreateOTP(uid UID, expiry Time) (*OTP, error)
	ReadOTP(token Token) (UID, error)
	DestroyOTP(token Token) error
}
