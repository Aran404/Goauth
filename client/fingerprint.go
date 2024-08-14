package client

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
)

func GetWindowsHWID() (string, error) {
	cmd := exec.Command("wmic", "csproduct", "get", "uuid")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	uuid := strings.ReplaceAll(string(output), "UUID", "")
	uuid = strings.TrimSpace(uuid)

	if strings.HasPrefix(uuid, "(") && strings.HasSuffix(uuid, ")") {
		uuid = uuid[1 : len(uuid)-1]
	}

	return uuid, nil
}

func StringToSHA256(content string) string {
	hasher := sha256.New()
	hasher.Write([]byte(content))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Error should be fatal
func GetFingerprint() (string, error) {
	hwid, err := GetWindowsHWID()
	if err != nil {
		return "", err
	}

	hostName, err := os.Hostname()
	if err != nil {
		return "", err
	}

	user, err := user.Current()
	if err != nil {
		return "", err
	}

	hwid = base64.StdEncoding.EncodeToString([]byte(hwid))
	encoded := fmt.Sprint(user.Username + hostName + hwid)
	return StringToSHA256(encoded), nil
}
