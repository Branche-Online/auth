package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	"github.com/branche-online/auth"
	"github.com/google/uuid"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"github.com/nrednav/cuid2"
)

// TokenAlgorithm is a type representing the algorithm used for token generation.
type TokenAlgorithm string

// TokenAlgorithm constants
// These constants represent the different algorithms that can be used for token generation.
// The supported algorithms are:
// - CUID2: A unique identifier generator that is designed to be collision-resistant.
// - UUIDv4: A universally unique identifier (UUID) generator that uses random numbers.
// - NANOID: A small, secure, URL-friendly, unique string ID generator.
// - RANDB10: A random string generator that uses base 10 characters.
// - RANDHEX: A random string generator that uses hexadecimal characters.
// - RANDB32: A random string generator that uses base 32 characters.
// - RANDB64: A random string generator that uses base 64 characters.
// - ALPHA: A random string generator that uses alphanumeric characters.
// - CUSALPHA: A random string generator that uses a custom alphabet.
// The custom alphabet must be provided in the TokenGeneratorOptions struct.
// The length of the generated token is specified in the TokenGeneratorOptions struct.
// The length must be greater than 0.
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

// ALPHABET is a string containing all the characters that can be used in the default alphabet.
// It includes lowercase and uppercase letters, as well as digits from the standard english alphabet.
const ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// randomChars generates a random string of the specified length using the provided alphabet.
// The function uses the crypto/rand package to generate cryptographically secure random numbers.
// It returns an error if the length is less than or equal to 0, or if there is an error generating the random string.
// The generated string will contain characters from the specified alphabet.
// The length of the generated string is specified by the length parameter.
// The length must be greater than 0.
// The function returns the generated string and nil error if successful.
// If the length is less than or equal to 0, the function returns an empty string and an error.
// If there is an error generating the random string, the function returns an empty string and the error.
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

// LoadRSAKeyFromPEM loads an RSA private key from a PEM file.
// The function takes the path to the PEM file as input and returns the parsed RSA private key.
// If the PEM file cannot be read or the key cannot be parsed, an error is returned.
// The function supports both PKCS1 and PKCS8 formats for the RSA private key.
// The PEM file must contain a valid RSA private key in one of these formats.
// The PEM data must be in the format:
// -----BEGIN RSA PRIVATE KEY-----
// <base64-encoded key>
// -----END RSA PRIVATE KEY-----
// or
// -----BEGIN PRIVATE KEY-----
// <base64-encoded key>
// -----END PRIVATE KEY-----
// The function returns the parsed RSA private key and nil error if successful.
// If the PEM file cannot be read or the key cannot be parsed, the function returns nil and an error.
func LoadRSAKeyFromPEM(path string) (*rsa.PrivateKey, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file: %v", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil || (block.Type != "RSA PRIVATE KEY" && block.Type != "PRIVATE KEY") {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	var parsedKey any
	if block.Type == "RSA PRIVATE KEY" {
		parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else {
		parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}

	return rsaKey, nil
}

// LoadRSAKeyFromMemory loads an RSA private key from a PEM string.
// The function takes a string containing the PEM data as input and returns the parsed RSA private key.
// If the PEM data cannot be parsed, an error is returned.
// The function supports both PKCS1 and PKCS8 formats for the RSA private key.
// The PEM data must contain a valid RSA private key in one of these formats.
// The function returns the parsed RSA private key and nil error if successful.
// If the PEM data cannot be parsed, the function returns nil and an error.
// The PEM data must be in the format:
// -----BEGIN RSA PRIVATE KEY-----
// <base64-encoded key>
// -----END RSA PRIVATE KEY-----
// or
// -----BEGIN PRIVATE KEY-----
// <base64-encoded key>
// -----END PRIVATE KEY-----
// The function will decode the PEM data and parse the RSA private key.
func LoadRSAKeyFromMemory(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || (block.Type != "RSA PRIVATE KEY" && block.Type != "PRIVATE KEY") {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	var parsedKey any
	var err error

	if block.Type == "RSA PRIVATE KEY" {
		parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else {
		parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}

	return rsaKey, nil
}

// RSKATokenVerifier is a struct that implements the TokenVerifier interface for RSA keys.
type RSKATokenVerifier struct {
	pss       *rsa.PSSOptions
	publicKey *rsa.PublicKey
}

// NewRSKATokenVerifier creates a new RSKATokenVerifier with the provided public key and PSS options.
// The public key must be a valid RSA public key.
// The PSS options can be nil if PSS is not used.
// The function returns a pointer to the RSKATokenVerifier struct.
func NewRSKATokenVerifier(publicKey *rsa.PublicKey, pss *rsa.PSSOptions) *RSKATokenVerifier {
	return &RSKATokenVerifier{
		publicKey: publicKey,
		pss:       pss,
	}
}

// Verify verifies the token using the public key and returns true if valid, false otherwise.
// If the verification is successful, it returns true and nil error.
// If the verification fails, it returns false and the error.
// The function uses the crypto/rsa package to verify the token.
// The token is verified using the public key and the signature.
// The function takes the token, hash, and signature as input parameters.
// The hash is the hash function used to generate the signature.
// The signature is the signature generated by the private key.
// The function returns true if the token is valid, false otherwise.
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

// ECDSATokenVerifier is a struct that implements the TokenVerifier interface for ECDSA keys.
type ECDSATokenVerifier struct {
	publicKey *ecdsa.PublicKey
}

// NewECDSATokenVerifier creates a new ECDSATokenVerifier with the provided public key.
func NewECDSATokenVerifier(publicKey *ecdsa.PublicKey) *ECDSATokenVerifier {
	return &ECDSATokenVerifier{
		publicKey: publicKey,
	}
}

// Verify verifies the token using the public key and returns true if valid, false otherwise.
// If the verification is successful, it returns true and nil error.
// If the verification fails, it returns false and the error.
// The function uses the crypto/ecdsa package to verify the token.
// The token is verified using the public key and the signature.
// The function takes the token, hash, and signature as input parameters.
// The hash is the hash function used to generate the signature.
// The signature is the signature generated by the private key.
// The function returns true if the token is valid, false otherwise.
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

// TokenGeneratorOptions is a struct that contains options for generating tokens.
// The struct contains the algorithm to be used for token generation, the length of the token,
// and an optional custom alphabet.
// The algorithm must be one of the supported algorithms defined in the TokenAlgorithm constants.
// The length must be greater than 0.
// The custom alphabet must be provided if the algorithm is CUSALPHA.
// The struct is used as input to the GenerateToken function in the TokenManager interface.
type TokenGeneratorOptions struct {
	Algorithm TokenAlgorithm
	Length    uint
	Alphabet  *string
}

// StandardTokenManager is a struct that implements the TokenManager interface.
// The struct contains a signer, a hash function, and a token verifier.
// The signer is used to sign the tokens, the hash function is used to generate a hash of the token,
// and the token verifier is used to verify the tokens.
// The struct is used to generate, sign, and verify tokens.
// The signer must be a valid crypto.Signer implementation.
// The hash function must be a valid crypto.Hash implementation.
// The token verifier must be a valid TokenVerifier implementation.
type StandardTokenManager struct {
	signer   crypto.Signer
	hash     crypto.Hash
	verifier auth.TokenVerifier
}

// NewStandardTokenManager creates a new StandardTokenManager with the provided signer, hash function, and token verifier.
// The signer must be a valid crypto.Signer implementation.
// The hash function must be a valid crypto.Hash implementation.
// The token verifier must be a valid TokenVerifier implementation.
// The function returns a pointer to the StandardTokenManager struct.
// The signer, verifier and hash function must be initialized before calling this function.
func NewStandardTokenManager(signer crypto.Signer, hash crypto.Hash, verifier auth.TokenVerifier) *StandardTokenManager {
	return &StandardTokenManager{
		signer:   signer,
		hash:     hash,
		verifier: verifier,
	}
}

// GenerateToken generates a token based on the provided options specified in the data parameter.
// The data parameter should be a pointer to a TokenGeneratorOptions struct.
// The function should return a token of the specified length and algorithm.
// If the algorithm is not recognized, return an error.
// If the length is not valid, return an error.
// If the alphabet is not valid, return an error.
// If the token generation is successful, return the generated token and nil error.
// If the token generation fails, return an empty token and the error.
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

// SignToken signs the token using the TokenManager's signer and returns the signature.
// The function takes the token as input and returns the signature and nil error if successful.
// If the signing fails, it returns an empty signature and the error.
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

// VerifyToken verifies the token using the TokenManager's verifier and returns true if valid, false otherwise.
// If the verification is successful, it returns true and nil error.
// If the verification fails, it returns false and the error.
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
