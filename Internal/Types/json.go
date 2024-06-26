package types

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

type Config struct {
	Verbose        bool  `json:"verbose"`
	DestroySession int64 `json:"destroy_session"`
	Security       struct {
		AllowedContext uint64 `json:"allowed_context"`
		Ratelimiter    bool   `json:"ratelimiter"`
		Ratelimit      int    `json:"ratelimit"`
		RatelimitExp   int    `json:"ratelimit_expiration"`
	} `json:"security"`
	Crypto struct {
		AccessTokenExpiry  int64 `json:"access_token_expiry"`
		RefreshTokenExpiry int64 `json:"refresh_token_expiry"`
	} `json:"crypto"`
	Mongo struct {
		Host     string `json:"host"`
		Database string `json:"database"`
		Timeout  int    `json:"timeout"`
	} `json:"mongo"`
}

var (
	Cfg        *Config = InitConfig()
	ConfigPath         = "./Config.json"
)

func WaitForChanges(c *Config, path string) {
	for {
		LoadJsonUnsafe(path, c)
		time.Sleep(time.Millisecond * 100)
	}
}

func LoadJson(file string, c any) {
	jsonFile, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}

	defer jsonFile.Close()
	if err := json.NewDecoder(jsonFile).Decode(&c); err != nil {
		log.Fatal(err)
	}
}

// Errors are ignored
func LoadJsonUnsafe(file string, c any) {
	jsonFile, _ := os.Open(file)
	defer jsonFile.Close()
	json.NewDecoder(jsonFile).Decode(&c)
}

func InitConfig() *Config {
	var config *Config
	LoadJson(ConfigPath, &config)
	go WaitForChanges(config, ConfigPath)

	return config
}
