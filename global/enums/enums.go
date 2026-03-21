package enums

//
// These enums are for logging

var (
	Register       = "register"
	Login          = "login"
	Logout         = "logout"
	Delete         = "delete"
	Refresh        = "refresh"
	ForgotPassword = "forgot-password"
	ChangePassword = "change-password"

	RegisterMFA   = "register-mfa"
	LoginMFA      = "login-mfa"
	PasswordReset = "password-reset"
)

//
// These enums are for IDENTIFYING MFA_TYPE in the program logic and DB

var (
	MfaRegVerify      = "register-verify"
	MfaLoginVerify    = "mfa-login-verify"
	MfaForgotPassword = "forgot-password-verify"
	MfaChangePassword = "change-password-verify"
)
