package client

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

func GetSignature() (string, error) {
	file, err := os.Open(strings.Join(os.Args, ""))
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	bytes := hash.Sum(nil)
	signature := hex.EncodeToString(bytes)
	return signature, nil
}
