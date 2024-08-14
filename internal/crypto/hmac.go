package crypto

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"math/rand"
)

// DeriveKey derives a key from the provided private key and seed.
// It is dually noted that this function should be implemented customly for your own application.
// If a bad actor see's the code on how you implement the derivation, they can easily derive the HMAC key.
// Although HMAC is not typically needed, it's an additional layer of security.
func DeriveKey(priv [32]byte, seed int64) [32]byte {
	// Although here it's purely seed based, you can easily add arithmetics to your seed to make it more secure.
	// For Example:
	// seed = (seed << 32) + (seed >> 32) + seed^2

	// The primary goal is to waste the bad actor's time.
	r := rand.New(rand.NewSource(seed))

	for n := len(priv); n > 0; n-- {
		randIndex := r.Intn(n)
		priv[n-1], priv[randIndex] = priv[randIndex], priv[n-1]
	}

	return priv
}

// GenerateHMAC generates an HMAC-SHA512 hash for the given message using the provided secret key.
func GenerateHMAC(message []byte, secretKey [32]byte) string {
	hash := hmac.New(sha512.New, secretKey[:])
	hash.Write(message)
	return hex.EncodeToString(hash.Sum(nil))
}

// VerifyHMAC verifies the given HMAC-SHA512 hash.
func VerifyHMAC(proper, expected []byte) bool {
	return hmac.Equal(proper, expected)
}
