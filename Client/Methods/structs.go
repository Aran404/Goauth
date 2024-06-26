package sdk

import (
	"fmt"
	"time"

	http "github.com/Aran404/goauth/Client/HTTP"
	websocket "github.com/Aran404/goauth/Client/Websocket"
	types "github.com/Aran404/goauth/Internal/Types"
)

type Client struct {
	*http.Client
	auth    *LoginInfo
	OwnerID string
}

type License struct {
	OwnerID       string `json:"owner_id"`
	Expiry        uint64 `json:"expiry"`
	AppID         string `json:"app_id"`
	AppName       string `json:"name"`
	Mask          string `json:"mask,omitempty"`
	OnlyCapitals  bool   `json:"include_capitals,omitempty"`
	OnlyLowercase bool   `json:"include_lowercase,omitempty"`
}

type LicenseValidate struct {
	IntegritySignature string `json:"integrity_signature"`
	Fingerprint        string `json:"fingerprint"`
	AppID              string `json:"app_id"`
	OwnerID            string `json:"owner_id"`
	LicenseKey         string `json:"license_key"`
}

type LoginInfo struct {
	RefreshToken string `mapstructure:"refresh_token"`
	Token        string `mapstructure:"token"`
}

func NewClient(c *websocket.Client, host string) *Client {
	r := http.NewClient(c, host)
	return &Client{
		Client: r,
	}
}

func ParseEncryptedResponse(body map[string]any) error {
	success, ok := body["success"].(bool)
	if !ok {
		return types.ErrorEmptyBody
	}

	if !success {
		if err, ok := body["error"].(string); ok {
			return fmt.Errorf("failed request, error: %v", err)
		}

		return fmt.Errorf("failed request")
	}

	context, ok := body["context"].(float64)
	if !ok {
		return types.ErrorEmptyBody
	}

	if time.Now().Unix() >= int64(context) {
		return types.ErrorContextExpired
	}

	return nil
}
