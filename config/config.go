package config

import (
	"encoding/json"
	"os"
	"time"
)

//
// Main Config File

type Config struct {
	EnvFile    string `json:"env"`            // ENV FILE NAME
	RedisCache bool   `json:"redis"`          // true OR false FOR USING REDIS CACHING
	MailingCfg string `json:"mailing-config"` // ADDRESS MAILING CONFIG FILE (RELATIVE TO PROJECT ROOT) - LEAVE EMPTY TO DISABLE MAILING
	HandlerCfg string `json:"handler-config"` // ADDRES HANDLER CONFIG FILE (RELATIVE TO PROJECT ROOT)
}

//
// Handler Config File

type HandlerConfig struct {
	Router RouterConfig `json:"router"`
	Cookie CookieConfig `json:"cookie"`
	JWT    JWTConfig    `json:"jwt"`
	MfaExp Duration     `json:"mfa-token-expiration"`           // HOW LONG IS MFA TOKEN VALID FOR (temporary helper token - it should be very short)
	Code   Duration     `json:"verification-code-queryTimeout"` // HOW LONG CAN DB BLOCK IN VERIFICATION RUN FOR
}

//
// Mailing Config File

type MailConfig struct {
	MailTimeout      Duration `json:"mail-timeout"`         // HOW LONG CAN EMAIL RUN FOR WHILE BEING SENT
	RegExpiry        Duration `json:"register-mail-expiry"` // HOW LONG UNTIL REGISTER (EMAIL VERIFICATION) CODE EXPIRY
	MfaLoginExpiry   Duration `json:"mfalogin-mail-expiry"` // HOW LONG UNTIL MFA_LOGIN CODE EXPIRY
	ChangePassExpiry Duration `json:"changepass-expiry"`    // HOW LONG UNTIL CHANGING PASSWORD CODE EXPIRY
	ForgotPassExpiry Duration `json:"forgotpass-expiry"`    // HOW LONG UNTIL FORGOT PASSWORD CODE EXPIRY
}

//
// Duration type for parsing JSON time to GO

type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {

	var s string

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	parsed, err := time.ParseDuration(s)

	if err != nil {
		return err
	}

	*d = Duration(parsed)

	return nil
}

//
// Sub Structs from Handler Config File

type RouterConfig struct {
	Timeout     Duration `json:"timeout"`     // HOW LONG CAN REQUEST RUN FOR (LIMITING RESOURCE USAGE)
	RequestSize int64    `json:"requestSize"` // HOW LARGE CAN REQUEST BE (LIMITING RESOURCE USAGE)
}

type CookieConfig struct {
	QueryTimeout           Duration `json:"queryTimeout"`             // HOW LONG CAN DB BLOCK IN COOKIE AUTH RUN FOR
	SessionTokenExpiration Duration `json:"session-token-expiration"` // HOW LONG IS SESSION TOKEN VALID FOR
	RefreshTokenExpiration Duration `json:"refresh-token-expiration"` // HOW LONG IS REFRESH TOKEN VALID FOR
}

type JWTConfig struct {
	QueryTimeout           Duration `json:"queryTimeout"`             // HOW LONG CAN DB BLOCK IN JWT AUTH RUN FOR
	JwtTokenExpiration     Duration `json:"jwt-token-expiration"`     // HOW LONG IS JWT TOKEN VALID FOR
	RefreshTokenExpiration Duration `json:"refresh-token-expiration"` // HOW LONG IS REFRESH TOKEN VALID FOR
	SpecialName            string   `json:"specialName"`              // NAME OF YOUR API (ONE OF THE CLAIMS IN THE JWT) - THIS IS NOT TO BE CONFUSED WITH THE SECRET
}

//
// LOADING JSON FILE INTO VARIOUS STRUCTS (TO BE USED CAREFULLY)

func Load[T any](path string) (T, error) {
	var cfg T

	data, err := os.ReadFile(path)

	if err != nil {
		return cfg, err
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}
