package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
)

func GenerateNonce() (*[12]byte, error) {
	nonce := [12]byte{}
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return &nonce, nil
}

// Encrypt encrypts the data using AES-GCM.
func Encrypt(data []byte, key [32]byte, nonce [12]byte) (string, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	cipherText := aesGCM.Seal(nil, nonce[:], data, nil)
	return hex.EncodeToString(cipherText), nil
}

// Decrypt decrypts the AES-GCM encrypted data.
func Decrypt(cipherTextHex string, key [32]byte, nonce [12]byte) ([]byte, error) {
	cipherText, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plainText, err := aesGCM.Open(nil, nonce[:], cipherText, nil)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}
