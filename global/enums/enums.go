package enums

//
// These enums are for LOGGING

const (
	Register       = "register"
	Login          = "login"
	Logout         = "logout"
	Delete         = "delete"
	Refresh        = "refresh"
	ForgotPassword = "forgot-password"
	ChangePassword = "change-password"

	MFARegister   = "register-mfa"
	MFALogin      = "login-mfa"
	PasswordReset = "password-reset"
	MFADelete     = "delete-mfa"

	AdminPromote  = "admin-promote"
	AdminRestrict = "admin-restrict"
	AdminDelete   = "admin-delete"
)

//
// These enums are for IDENTIFYING MFA_TYPE in the program logic and DB

const (
	MfaRegVerify      = "register-verify"
	MfaLoginVerify    = "mfa-login-verify"
	MfaForgotPassword = "forgot-password-verify"
	MfaChangePassword = "change-password-verify"
	MfaDeleteVerify   = "mfa-delete-verify"
)

//
// These enums are for EXTRACTING IDENTIFIERS

const (
	CtxUsernameEmail   = "username-email"
	CtxSessionToken    = "session-token"
	CtxMfaSessionToken = "mfa-session-token"
	CtxJWT             = "authorization-jwt"
)
