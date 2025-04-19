package otp

import (
	"errors"
	"time"

	"github.com/branche-online/auth"
	"github.com/branche-online/auth/adapter/token"
)

type UIDToken struct {
	UID   auth.UID
	Token auth.Token
}

type OTPData struct {
	CreatedAt auth.Time
	TTL       auth.Duration
}

// OTPDbManager is the struct that represents the OTP manager
// It is used to manage the OTPs in memory
// It implements the OTPManager interface
// It is used to create, read and destroy OTPs in memory
type OTPInMemoryManager struct {
	otps   map[UIDToken]OTPData
	gen    *token.StandardTokenManager
	tkopts *token.TokenGeneratorOptions
}

// NewOTPDbManager is a constructor for OTPDbManager and returns new OTPDbManager.
// It takes a Token Generator options, and a StandardTokenManager as input
// It returns a new OTP manager and nil if initialization of the new manager is successful
// It returns an nil and an error if the initialization of the new manager fails
func NewOTPInMemoryManager(tkopts *token.TokenGeneratorOptions, tkgn *token.StandardTokenManager) (*OTPInMemoryManager, error) {
	otpMgr := &OTPInMemoryManager{}
	var err error

	// Set the token generator
	// It is used to generate the token for the OTP
	if tkgn == nil {
		return nil, errors.New("token generator not initialized")
	}
	otpMgr.gen = tkgn

	if tkopts == nil {
		tkopts = &token.TokenGeneratorOptions{
			Algorithm: token.RANDB10,
			Length:    6,
			Alphabet:  nil,
		}
	}
	otpMgr.tkopts = tkopts

	return otpMgr, err
}

// GetTokenGenerator returns the token generator
// It returns the token generator used by the otp manager to generate tokens for the OTPs
// It returns an error if the token generator is nil
func (otpMgr *OTPInMemoryManager) GetTokenGenerator() (*token.StandardTokenManager, error) {
	if otpMgr.gen != nil {
		return otpMgr.gen, nil
	}
	return nil, errors.New("token generator not initialized")
}

// CreateOTP creates and registers a new OTP with the OTP manager
// It takes a user id and a time to live (TTL) as input
// It generates a new token using the token generator
// It returns an error if creation fails
// It returns the OTP object if creation is successful
// It returns nil and an error if the creation fails
func (otpMgr *OTPInMemoryManager) CreateOTP(uid auth.UID, ttl auth.Duration) (*auth.OTP, error) {
	// Check if the OTP manager is initialized
	var err error
	var tkgn *token.StandardTokenManager
	tkgn, err = otpMgr.GetTokenGenerator()

	if err != nil {
		otp := &auth.OTP{}
		var tk auth.Token
		tk, err = tkgn.GenerateToken(otpMgr.tkopts)
		if err != nil {
			otp.Token = tk
		} else {
			return nil, err
		}
		otp.UID = uid
		otp.CreatedAt = auth.Time(time.Now())
		otp.TTL = ttl

		otpMgr.otps[UIDToken{UID: otp.UID, Token: otp.Token}] = OTPData{
			CreatedAt: otp.CreatedAt,
			TTL:       otp.TTL,
		}

		return otp, nil
	}

	return nil, err
}

// ReadOTP reads an OTP from the OTP Manager
// It takes a token and a user id as input
// It returns the nil and an error if the OTP is not found
func (otpMgr *OTPInMemoryManager) ReadOTP(token auth.Token, uid auth.UID) (*auth.OTP, error) {

	otpdata, exists := otpMgr.otps[UIDToken{UID: uid, Token: token}]
	if !exists {
		return nil, errors.New("OTP not found")
	}

	otp := &auth.OTP{
		CreatedAt: otpdata.CreatedAt,
		Token:     token,
		UID:       uid,
		TTL:       otpdata.TTL,
	}

	return otp, nil
}

// DestroyOTP destroys an OTP in the OTP Manager
// It takes a token and a user id as input
// It returns an error if the OTP is not found
// It returns nil if the OTP is destroyed successfully
func (otpMgr *OTPInMemoryManager) DestroyOTP(token auth.Token, uid auth.UID) error {
	_, exists := otpMgr.otps[UIDToken{UID: uid, Token: token}]
	if !exists {
		return errors.New("OTP not found")
	}

	delete(otpMgr.otps, UIDToken{UID: uid, Token: token})

	return nil
}
