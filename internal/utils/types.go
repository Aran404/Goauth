package utils

import "regexp"

func Btoi(b bool) int8 {
	if b {
		return 1
	}
	return 0
}

func StringsToBytes(s []string) []byte {
	var bytes []byte
	for _, v := range s {
		bytes = append(bytes, []byte(v)...)
	}
	return bytes
}

func CheckPassword(password string) bool {
	// Minimum eight characters, at least one letter, one number and one special character
	expression := `^(.{0,7}|[^0-9]*|[^A-Z]*|[^a-z]*|[a-zA-Z0-9]*)$`
	match, _ := regexp.MatchString(expression, password)
	return !match
}
