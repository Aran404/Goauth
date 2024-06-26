package server

import (
	"encoding/json"
	"errors"
	"time"

	types "github.com/Aran404/goauth/Internal/Types"
	utils "github.com/Aran404/goauth/Internal/Utils"
	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
)

func (s *Server) GenerateKeyPair(username string, admin int8) (*fiber.Map, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"username": username,
		"admin":    admin,
		"exp":      time.Now().Add(time.Minute * time.Duration(types.Cfg.Crypto.AccessTokenExpiry)).Unix(),
	})

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"username": username,
		"admin":    admin,
		"exp":      time.Now().Add(time.Minute * time.Duration(types.Cfg.Crypto.RefreshTokenExpiry)).Unix(),
	})

	signedToken, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return nil, err
	}

	signedRefreshToken, err := refreshToken.SignedString(s.jwtSecret)
	if err != nil {
		return nil, err
	}

	dump := &fiber.Map{"token": signedToken, "refresh_token": signedRefreshToken, "success": true, "context": time.Now().Unix() + int64(types.Cfg.Security.AllowedContext)}
	return dump, nil
}

func (s *Server) RefreshAccessToken(c fiber.Ctx) error {
	refreshToken := c.Cookies("refresh_token")
	if refreshToken == "" {
		return types.ErrorNoRefreshToken
	}

	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("Unexpected signing method")
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid refresh token"})
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		username, ok := claims["username"].(string)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token claims"})
		}

		// Check if token is expired
		exp, ok := claims["exp"].(float64)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token claims"})
		}

		if time.Now().Unix() > int64(exp) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Refresh token expired"})
		}

		newToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
			"username": username,
			"exp":      time.Now().Add(time.Minute * time.Duration(types.Cfg.Crypto.AccessTokenExpiry)).Unix(),
		})

		signedToken, err := newToken.SignedString(s.jwtSecret)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to sign new token"})
		}

		return c.JSON(fiber.Map{"token": signedToken})
	}

	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid refresh token"})
}

func (s *Server) parseJWTFields(c fiber.Ctx) (*UserJWT, error) {
	user, ok := c.Locals("user").(*jwt.Token)
	if !ok {
		return nil, fiber.ErrUnauthorized
	}

	claims, ok := user.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fiber.ErrUnauthorized
	}

	raw, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	var msg *UserJWT
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, types.ErrorInvalidJSON
	}

	if utils.CheckEmptyFields(msg) {
		return nil, types.ErrorEmptyFields
	}

	return msg, nil
}
