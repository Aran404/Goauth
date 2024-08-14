package crypto

import (
	"crypto/rand"
	"encoding/base64"

	log "github.com/Aran404/Goauth/internal/logger"
	utils "github.com/Aran404/Goauth/internal/utils"
)

func GenerateJWTKey(length int) string {
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(log.GetStackTrace(), "Could not generate API key: %v", err.Error())
	}
	return base64.StdEncoding.EncodeToString(key)
}

func GenerateAPIKey(keySize int) (string, error) {
	byteSize := keySize * 6 / 8
	if keySize*6%8 > 0 {
		byteSize++
	}

	bytes := make([]byte, byteSize)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	apiKey := base64.URLEncoding.EncodeToString(bytes)
	if len(apiKey) > keySize {
		return apiKey[:keySize], nil
	}

	return apiKey + utils.GenerateRandomString(keySize-len(apiKey)), nil
}

func GenerateRawKey(length int) []byte {
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(log.GetStackTrace(), "Could not generate key: %v", err.Error())
	}
	return key
}
