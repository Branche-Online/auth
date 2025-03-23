package auth

type AuthenticationAdapter interface {
	TokenMaker
	SessionManager
	AccountManager
}
