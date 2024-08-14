package utils

import (
	"math/rand"
	"strings"
	"time"
)

var (
	CapitalList   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	LowercaseList = "abcdefghijklmnopqrstuvwxyz"
	NumbersList   = "0123456789"
)

type LicenseSettings struct {
	Mask          string
	OnlyCapitals  bool
	OnlyLowercase bool
}

func CreateLicense(s ...LicenseSettings) string {
	rand.New(rand.NewSource(time.Now().UnixNano()))
	charList := NumbersList

	defaultMask := "****-****-****-****"
	if len(s) > 0 {
		if s[0].Mask != "" {
			defaultMask = s[0].Mask
		}

		if s[0].OnlyCapitals {
			charList += CapitalList
		}

		if s[0].OnlyLowercase {
			charList += LowercaseList
		}

		if !(s[0].OnlyCapitals || s[0].OnlyLowercase) {
			charList += CapitalList + LowercaseList
		}
	}

	b := new(strings.Builder)
	for _, v := range defaultMask {
		if v == '*' {
			n := rand.Intn(len(charList))
			b.WriteByte(charList[n])
		} else {
			b.WriteRune(v)
		}
	}

	return b.String()
}

func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
