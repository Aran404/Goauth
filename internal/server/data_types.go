package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	crypto "github.com/Aran404/Goauth/internal/crypto"
	"github.com/gofiber/fiber/v3"
)

type (
	LicenseMsg struct {
		IntegritySignature string `json:"integrity_signature"`
		Fingerprint        string `json:"fingerprint"`
		AppID              string `json:"app_id"`
		OwnerID            string `json:"owner_id"`
		LicenseKey         string `json:"license_key"`
	}

	UserMsg struct {
		APIKey   string `json:"api_key,omitempty"`
		Username string `json:"username"`
		Password string `json:"password"`
	}

	UserJWT struct {
		Username string  `json:"username"`
		Exp      float64 `json:"exp"`
		Admin    int8    `json:"admin"`
	}

	NewApplicationMsg struct {
		OwnerID string `json:"owner_id"`
		Name    string `json:"name"`
	}

	NewLicenseMsg struct {
		OwnerID       string `json:"owner_id"`
		Expiry        uint64 `json:"expiry"`
		AppID         string `json:"app_id"`
		AppName       string `json:"name"`
		Mask          string `json:"mask,omitempty"`
		OnlyCapitals  bool   `json:"include_capitals,omitempty"`
		OnlyLowercase bool   `json:"include_lowercase,omitempty"`
	}
)

func (s *Server) EncryptJson(c fiber.Ctx, plainText any, session *Session) error {
	encoded, err := json.Marshal(plainText)
	if err != nil {
		return fmt.Errorf("Could not marshal json, Error: %v", err)
	}

	encrypted, err := crypto.Encrypt(encoded, session.PrivateKey, session.Nonce)
	if err != nil {
		return fmt.Errorf("Could not encrypt json, Error: %v", err)
	}

	if err := s.IntegrityMiddleware(c, []byte(encrypted)); err != nil {
		return err
	}

	_, err = c.Status(http.StatusOK).WriteString(encrypted)
	return err
}
