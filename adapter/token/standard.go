package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/branche-online/auth"
	"github.com/google/uuid"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"github.com/nrednav/cuid2"
)

type TokenAlgorithm string

const (
	CUID2    TokenAlgorithm = "cuid2"
	UUIDv4   TokenAlgorithm = "uuidv4"
	NANOID   TokenAlgorithm = "nano-id"
	RANDB10  TokenAlgorithm = "randb10"
	RANDHEX  TokenAlgorithm = "randhex"
	RANDB32  TokenAlgorithm = "randb32"
	RANDB64  TokenAlgorithm = "randb64"
	ALPHA    TokenAlgorithm = "alphabet"
	CUSALPHA TokenAlgorithm = "custom-alphabet"
)

const ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomChars(alphabet string, length uint) (string, error) {
	if length == 0 {
		return "", fmt.Errorf("length must be greater than 0")
	}

	b := make([]rune, length)
	for i := range b {
		max := big.NewInt(int64(len(alphabet)))
		rIdx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("failed to generate random index: %w", err)
		}
		b[i] = rune(alphabet[rIdx.Int64()])
	}
	return string(b), nil
}

type RSKATokenVerifier struct {
	pss       *rsa.PSSOptions
	publicKey *rsa.PublicKey
}

func NewRSKATokenVerifier(publicKey *rsa.PublicKey, pss *rsa.PSSOptions) *RSKATokenVerifier {
	return &RSKATokenVerifier{
		publicKey: publicKey,
		pss:       pss,
	}
}

func (rsatkv *RSKATokenVerifier) Verify(tkn auth.Token, hash crypto.Hash, sig []byte) (bool, error) {
	// Verify the token using the public key and return true if valid, false otherwise.
	// If the verification is successful, return true and nil error.
	// If the verification fails, return false and the error.

	if rsatkv.publicKey == nil {
		return false, fmt.Errorf("rsa public key is not initialized")
	}

	if hash == 0 {
		return false, fmt.Errorf("hash is not initialized")
	}

	hashFunc := hash.New()
	// Generate a digest from the token that will be passed to the rsa verifier
	tokenDigest := hashFunc.Sum([]byte(tkn))

	verified := false
	var err error

	// Verify the token using the public key and the signature
	if rsatkv.pss == nil {
		err = rsa.VerifyPKCS1v15(rsatkv.publicKey, hash, tokenDigest, sig)

		if err != nil {
			verified = false
		} else {
			verified = true
		}
	} else {
		err = rsa.VerifyPSS(rsatkv.publicKey, hash, tokenDigest, sig, rsatkv.pss)

		if err != nil {
			verified = false
		} else {
			verified = true
		}
	}

	return verified, err
}

type ECDSATokenVerifier struct {
	publicKey *ecdsa.PublicKey
}

func NewECDSATokenVerifier(publicKey *ecdsa.PublicKey) *ECDSATokenVerifier {
	return &ECDSATokenVerifier{
		publicKey: publicKey,
	}
}

func (ecdsatkv *ECDSATokenVerifier) Verify(tkn auth.Token, hash crypto.Hash, sig []byte) (bool, error) {
	// Verify the token using the public key and return true if valid, false otherwise.
	// If the verification is successful, return true and nil error.
	// If the verification fails, return false and the error.

	if ecdsatkv.publicKey == nil {
		return false, fmt.Errorf("rsa public key is not initialized")
	}

	if hash == 0 {
		return false, fmt.Errorf("hash is not initialized")
	}

	hashFunc := hash.New()
	// Generate a digest from the token that will be passed to the rsa verifier
	tokenDigest := hashFunc.Sum([]byte(tkn))

	// Verify the token using the public key and the signature
	verified := ecdsa.VerifyASN1(ecdsatkv.publicKey, tokenDigest, sig)

	return verified, nil
}

type TokenGeneratorOptions struct {
	Algorithm TokenAlgorithm
	Length    uint
	Alphabet  *string
}

type StandardTokenManager struct {
	signer   crypto.Signer
	hash     crypto.Hash
	verifier auth.TokenVerifier
}

func NewStandardTokenManager(signer crypto.Signer, hash crypto.Hash, verifier auth.TokenVerifier) *StandardTokenManager {
	return &StandardTokenManager{
		signer:   signer,
		hash:     hash,
		verifier: verifier,
	}
}

func (tknMgr *StandardTokenManager) GenerateToken(data any) (auth.Token, error) {
	// Generate a token based on the provided options specified in the data parameter.
	// The data parameter should be a pointer to a TokenGeneratorOptions struct.
	// The function should return a token of the specified length and algorithm.
	// If the algorithm is not recognized, return an error.
	// If the length is not valid, return an error.
	// If the alphabet is not valid, return an error.
	// If the token generation is successful, return the generated token and nil error.
	// If the token generation fails, return an empty token and the error.

	var err error
	var tkn string = ""

	opts, ok := data.(*TokenGeneratorOptions)

	if opts == nil || !ok {
		return "", fmt.Errorf("invalid token generator options data type: %T", data)
	}

	switch opts.Algorithm {
	case CUID2:
		cuid2Gen, err := cuid2.Init(
			cuid2.WithLength(int(opts.Length)),
		)
		if err != nil {
			return "", fmt.Errorf("failed to initialize cuid2 generator: %w", err)
		}

		tkn = cuid2Gen()
	case UUIDv4:
		uuidTkn, err := uuid.NewRandom()
		if err != nil {
			return "", fmt.Errorf("failed to generate UUIDv4 token: %w", err)
		}
		tkn = uuidTkn.String()
	case NANOID:
		if opts.Alphabet != nil || len(*opts.Alphabet) > 0 {
			tkn, err = gonanoid.Generate(*opts.Alphabet, int(opts.Length))
		} else {
			tkn, err = gonanoid.New()
		}

		if err != nil {
			return "", fmt.Errorf("failed to generate nanoid token: %w", err)
		}
	case RANDB10:
		base10 := auth.B10
		tkn, err = auth.RandomString(&base10, opts.Length, nil)
	case RANDHEX:
		base16 := auth.HEX
		tkn, err = auth.RandomString(&base16, opts.Length, nil)
	case RANDB32:
		base32 := auth.B32
		tkn, err = auth.RandomString(&base32, opts.Length, nil)
	case RANDB64:
		base64 := auth.B64
		tkn, err = auth.RandomString(&base64, opts.Length, nil)
	case ALPHA:
		tkn, err = randomChars(ALPHABET, opts.Length)
	case CUSALPHA:
		if opts.Alphabet == nil || len(*opts.Alphabet) == 0 {
			return "", fmt.Errorf("custom alphabet must be provided for custom-alphabet algorithm")
		}
		tkn, err = randomChars(*opts.Alphabet, opts.Length)
	default:
		return "", fmt.Errorf("unsupported token generation algorithm: %s", opts.Algorithm)
	}
	return auth.Token(tkn), err
}

func (tknMgr *StandardTokenManager) SignToken(token auth.Token) (auth.Digest, error) {
	// Sign the token using the provided secret key and return the signature.
	// The function should use the crypto.Signer interface to sign the token.
	// If the signing is successful, return the signature and nil error.
	// If the signing fails, return an empty signature and the error.

	if tknMgr.signer == nil {
		return "", fmt.Errorf("token manager signer is not initialized")
	}

	if tknMgr.hash == 0 {
		return "", fmt.Errorf("token manager hash is not initialized")
	}

	// Load the hashFunc associated with the hash specified by the token manager
	hashFunc := tknMgr.hash.New()
	// Generate a digest from the token that will be passed to the signer to sign
	tokenDigest := hashFunc.Sum([]byte(token))

	signature, err := tknMgr.signer.Sign(rand.Reader, []byte(tokenDigest), tknMgr.hash)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return auth.Digest(signature), nil
}

func (tknMgr *StandardTokenManager) VerifyToken(token auth.Token, signature auth.Digest) (bool, error) {
	// Verify the token using the verifiers public key and return true if valid, false otherwise.
	// If the verification is successful, return true and nil error.
	// If the verification fails, return false and the error.

	if tknMgr.signer == nil {
		return false, fmt.Errorf("token manager signer is not initialized")
	}

	verified, err := tknMgr.verifier.Verify(token, tknMgr.hash, []byte(signature))
	if err != nil {
		return false, fmt.Errorf("failed to verify token: %w", err)
	}

	return verified, nil
}
