package types

import (
	"errors"
	"net/http"
)

var (
	ErrorInvalidHello = errors.New("invalid hello payload")

	// Database Errors
	ErrorNotPointer = errors.New("not a pointer")
	ErrorNotFound   = errors.New("not found")
	ErrorCollision  = errors.New("collision")
	ErrorNoMatches  = errors.New("no matches found")
	ErrorSafeSwitch = errors.New("safe switch is on")

	// HTTP Errors
	ErrorEmptyBody      = errors.New("invalid request")
	ErrorEmptyFields    = errors.New("empty fields")
	ErrorNoSession      = errors.New("no session")
	ErrorCannotDecrypt  = errors.New("cannot decrypt")
	ErrorNoRefreshToken = errors.New("no refresh token")
	ErrorInvalidJSON    = errors.New("invalid json")

	// Production Database Errors
	ErrorAccountExists     = errors.New("account already exists")
	ErrorIncorrectPassword = errors.New("incorrect password")
	ErrorInvalidUserID     = errors.New("invalid userID")
	ErrorApplicationExists = errors.New("application already exists")
	ErrorInvalidOwner      = errors.New("invalid owner")
	ErrorInvalidApp        = errors.New("invalid app")
	ErrorOwnerNotFound     = errors.New("owner not found")
	ErrorUserNotFound      = errors.New("user not found")

	// Validation Errors
	ErrorInvalidLicense     = errors.New("invalid license")
	ErrorExpiredLicense     = errors.New("license expired")
	ErrorInvalidFingerprint = errors.New("invalid fingerprint")
	ErrorInsecurePassword   = errors.New("insecure password")
	ErrorIncorrectLength    = errors.New("incorrect length")

	// Security Errors
	ErrorNoIntegrity      = errors.New("no integrity")
	ErrorInvalidIntegrity = errors.New("invalid integrity")
	ErrorContextExpired   = errors.New("context expired")

	// User Errors
	ErrorEmptyStruct = errors.New("empty struct")

	// Proper Errors
	properErrors = map[error]string{
		ErrorInvalidHello:       "Improper Hello Payload.",
		ErrorNotPointer:         "Value is not a valid pointer.",
		ErrorNotFound:           "Query not found.",
		ErrorCollision:          "Query collided.",
		ErrorNoMatches:          "No matches found.",
		ErrorSafeSwitch:         "Safe switch is currently on.",
		ErrorEmptyBody:          "Request body is empty.",
		ErrorEmptyFields:        "One or more fields are empty.",
		ErrorOwnerNotFound:      "OwnerID not found in database.",
		ErrorInvalidLicense:     "Invalid license key.",
		ErrorExpiredLicense:     "License key has expired.",
		ErrorInvalidFingerprint: "Authority fingerprint is invalid. You may only use a license on one device.",
		ErrorNoSession:          "No sessions found. Please create one.",
		ErrorNoIntegrity:        "No integrity signature found. Could be an attacker.",
		ErrorInvalidIntegrity:   "Integrity signature is invalid. Could be an attacker.",
		ErrorContextExpired:     "Context window has passed.",
		ErrorCannotDecrypt:      "Could not decrypt. Please verify encryption.",
		ErrorInvalidOwner:       "Invalid Owner ID.",
		ErrorInvalidApp:         "Invalid Application ID.",
		ErrorEmptyStruct:        "Empty data.",
		ErrorInsecurePassword:   "Insecure password. Please change it.",
		ErrorIncorrectLength:    "Your username is an incorrect length. Length must be between 3 and 20.",
		ErrorAccountExists:      "Account already exists.",
		ErrorIncorrectPassword:  "Incorrect password.",
		ErrorNoRefreshToken:     "No refresh token found.",
		ErrorInvalidUserID:      "Invalid UserID Provided.",
		ErrorApplicationExists:  "Application already exists.",
		ErrorInvalidJSON:        "Invalid JSON.",
		ErrorUserNotFound:       "User not found.",
	}

	errorType = map[error]int{
		ErrorInvalidHello:       http.StatusBadRequest,
		ErrorNotPointer:         http.StatusInternalServerError,
		ErrorNotFound:           http.StatusBadRequest,
		ErrorCollision:          http.StatusInternalServerError,
		ErrorNoMatches:          http.StatusInternalServerError,
		ErrorSafeSwitch:         http.StatusInternalServerError,
		ErrorEmptyBody:          http.StatusBadRequest,
		ErrorEmptyFields:        http.StatusBadRequest,
		ErrorOwnerNotFound:      http.StatusBadRequest,
		ErrorInvalidLicense:     http.StatusBadRequest,
		ErrorExpiredLicense:     http.StatusBadRequest,
		ErrorInvalidFingerprint: http.StatusBadRequest,
		ErrorNoSession:          http.StatusBadRequest,
		ErrorCannotDecrypt:      http.StatusBadRequest,
		ErrorNoIntegrity:        http.StatusBadRequest,
		ErrorInvalidIntegrity:   http.StatusBadRequest,
		ErrorContextExpired:     http.StatusBadRequest,
		ErrorInvalidOwner:       http.StatusBadRequest,
		ErrorInvalidApp:         http.StatusBadRequest,
		ErrorEmptyStruct:        http.StatusBadRequest,
		ErrorInsecurePassword:   http.StatusBadRequest,
		ErrorIncorrectLength:    http.StatusUnauthorized,
		ErrorAccountExists:      http.StatusBadRequest,
		ErrorIncorrectPassword:  http.StatusBadRequest,
		ErrorNoRefreshToken:     http.StatusBadRequest,
		ErrorInvalidUserID:      http.StatusBadRequest,
		ErrorApplicationExists:  http.StatusBadRequest,
		ErrorInvalidJSON:        http.StatusBadRequest,
		ErrorUserNotFound:       http.StatusBadRequest,
	}
)

func ProperError(err error) string {
	if v, ok := properErrors[err]; ok {
		return v
	}

	return err.Error()
}

func ErrorType(err error) int {
	if v, ok := errorType[err]; ok {
		return v
	}

	return http.StatusInternalServerError
}
