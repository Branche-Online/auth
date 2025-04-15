package auth

import (
	"crypto"
)

type Token string

type TokenVerifier interface {
	Verify(tkn Token, hash crypto.Hash, sig []byte) (bool, error)
}

type TokenManager interface {
	GenerateToken(data any) (Token, error)
	SignToken(token Token) (Digest, error)
	VerifyToken(token Token, signature Digest) (bool, error)
}
