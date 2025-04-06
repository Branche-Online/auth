package auth

type Token string

type TokenManager interface {
	GenerateToken(data any) (Token, error)
	SignToken(token Token, secret Key) (Digest, error)
	VerifyToken(token Token, signature Digest, publicKey Key) (bool, error)
}
