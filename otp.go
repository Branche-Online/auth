package auth

type OTP struct {
	CreatedAt Time     `json:"created_at"`
	Token     Token    `json:"token"`
	UID       UID      `json:"uid"`
	TTL       Duration `json:"ttl"`
}

type OTPManager interface {
	CreateOTP(uid UID, ttl Duration) (*OTP, error)
	ReadOTP(token Token) (UID, error)
	DestroyOTP(token Token) error
}
