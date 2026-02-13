package config

import (
	"encoding/json"
	"os"
	"time"
)

type Config struct {
	Env        string `json:"env"`
	Db         string `json:"db"`
	HandlerCfg string `json:"handler-config"`
}

type HandlerConfig struct {
	Router RouterConfig `json:"router"`
	Cookie CookieConfig `json:"cookie"`
	JWT    JWTConfig    `json:"jwt"`
}

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

type RouterConfig struct {
	Timeout     Duration `json:"timeout"`
	RequestSize int64    `json:"requestSize"`
}

type CookieConfig struct {
	QueryTimeout Duration `json:"queryTimeout"`
}

type JWTConfig struct {
	QueryTimeout Duration `json:"queryTimeout"`
	Expiration   Duration `json:"expiration"`
	SpecialName  string   `json:"specialName"`
}

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
