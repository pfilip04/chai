package enums

//
// These enums are for IDENTIFYING MFA_TYPE in the program logic and DB

var (
	MfaRegVerify      = "register-verify"
	MfaLoginVerify    = "mfa-login-verify"
	MfaForgotPassword = "forgot-password-verify"
	MfaChangePassword = "change-password-verify"
)

//
// These enums are for USER-FRIENDLY FEEDBACK MESSAGE to the user

var (
	Reg        = "Register"
	Login      = "Login"
	PassReset  = "Password-reset"
	PassChange = "Password-change"
)
