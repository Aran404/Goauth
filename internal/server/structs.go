package server

import (
	"context"
	"sync"

	crypto "github.com/Aran404/Goauth/internal/crypto"
	mongo "github.com/Aran404/Goauth/internal/database/mongo"
	redis "github.com/Aran404/Goauth/internal/database/redis"
	log "github.com/Aran404/Goauth/internal/logger"
	types "github.com/Aran404/Goauth/internal/types"
	"github.com/dgrr/fastws"
	"github.com/gofiber/fiber/v3"
)

type Server struct {
	rdb    *redis.Connection
	db     *mongo.Connection
	client *fiber.App

	smutex  *sync.Mutex
	dbmutex *sync.Mutex

	dbCtx     context.Context
	jwtSecret []byte
}

type LicenseHolders struct {
	msg     *LicenseMsg
	license *mongo.LicenseObject
	app     *mongo.ApplicationObject
}

type Session struct {
	PrivateKey [32]byte `json:"private_key" redis:"private_key"`
	HashKey    [32]byte `json:"hash_key" redis:"hash_key"`
	Nonce      [12]byte `json:"nonce" redis:"nonce"`
}

type SterlizedSession struct {
	PrivateKey string `json:"private_key" redis:"private_key"`
	HashKey    string `json:"hash_key" redis:"hash_key"`
	Nonce      string `json:"nonce" redis:"nonce"`
}

type Connection struct {
	*fastws.Conn
}

type Route struct {
	Method     string
	Path       string
	Func       fiber.Handler
	Restricted bool
}

func FromMap(m fiber.Map) *Session {
	return &Session{
		// Have to double type cast due to maps not being explicitly typed
		PrivateKey: ([32]byte)(m["private_key"].([]byte)),
		HashKey:    ([32]byte)(m["hash_key"].([]byte)),
		Nonce:      ([12]byte)(m["nonce"].(([]byte))),
	}
}

func (s *Server) ParseBody(c fiber.Ctx) (*Session, []byte, error) {
	body := c.Body()
	if len(body) == 0 {
		return nil, nil, types.ErrorEmptyBody
	}

	sessionID := c.GetReqHeaders()["X-Session-Id"]
	if len(sessionID) <= 0 || sessionID[0] == "" {
		return nil, nil, types.ErrorNoSession
	}

	rawSession := make(fiber.Map)
	if err := s.rdb.HGetAll(s.dbCtx, sessionID[0], rawSession); err != nil {
		log.Error(log.GetStackTrace(), "Could not get session, Error: %v", err.Error())
		return nil, nil, types.ErrorNoSession
	}
	session := FromMap(rawSession)

	decrypted, err := crypto.Decrypt(string(body), session.PrivateKey, session.Nonce)
	if err != nil {
		return nil, nil, err
	}

	if len(decrypted) == 0 {
		return nil, nil, types.ErrorEmptyBody
	}

	return session, decrypted, nil
}
