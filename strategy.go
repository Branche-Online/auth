package auth

type AuthStrategy interface {
	signIn(ssn *SessionManager, acc *AccountManager, tkn *TokenManager, otp *OTPManager, ud any) (*Session, error)
	signOut(ssn *SessionManager, acc *AccountManager, uid UID) error
	signUp(ssn *SessionManager, acc *AccountManager, tkn *TokenManager, otp *OTPManager, ud any) (*User, error)
}
