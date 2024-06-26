package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	crypto "github.com/Aran404/goauth/Internal/Crypto"
	jwtware "github.com/Aran404/goauth/Internal/Crypto/jwt"
	mongo "github.com/Aran404/goauth/Internal/Database/Mongo"
	redis "github.com/Aran404/goauth/Internal/Database/Redis"
	log "github.com/Aran404/goauth/Internal/Logger"
	types "github.com/Aran404/goauth/Internal/Types"
	utils "github.com/Aran404/goauth/Internal/Utils"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/requestid"
	"github.com/golang-jwt/jwt/v5"
)

func (s *Server) ErrorHandler(c fiber.Ctx, errResp error) error {
	if err, ok := errResp.(*fiber.Error); ok {
		return c.Status(err.Code).JSON(fiber.Map{"error": err.Message})
	}

	errType := types.ErrorType(errResp)
	errResp = errors.New(types.ProperError(errResp))

	plain := func() error {
		return c.Status(errType).JSON(fiber.Map{"error": errResp.Error(), "success": false})
	}

	sessionID := c.Get("X-Session-Id")
	if sessionID == "" {
		return plain()
	}

	exists, err := s.rdb.Exists(s.dbCtx, sessionID)
	if err != nil {
		log.Error(log.GetStackTrace(), "Could not check if session exists, Error: %v", err.Error())
		return plain()
	}

	if !exists {
		return plain()
	}

	rawSession := make(fiber.Map)
	if err := s.rdb.HGetAll(s.dbCtx, sessionID, rawSession); err != nil {
		log.Error(log.GetStackTrace(), "Could not get session, Error: %v", err.Error())
		return plain()
	}
	session := FromMap(rawSession)

	plainText := fiber.Map{
		"success": false,
		"error":   errResp.Error(),
		"context": uint64(time.Now().Unix()) + uint64(types.Cfg.Security.AllowedContext),
	}

	if err := s.EncryptJson(c, plainText, session); err != nil {
		log.Error(log.GetStackTrace(), err.Error())
		return fiber.ErrInternalServerError
	}

	return nil
}

func NewServer(dbCtx context.Context, rdb *redis.Connection, jwtSecret []byte) *Server {
	return &Server{
		rdb:     rdb,
		smutex:  &sync.Mutex{},
		db:      mongo.NewConn(dbCtx),
		dbCtx:   dbCtx,
		dbmutex: &sync.Mutex{},
	}
}

func (s *Server) Clean() error {
	if err := s.rdb.Client.Close(); err != nil {
		return err
	}

	s.db.Close(s.dbCtx)
	s.dbCtx.Done()
	return nil
}

func (s *Server) ServerOptions(e ...fiber.Handler) {
	for _, v := range e {
		s.client.Use(v)
	}
}

func (s *Server) DefaultOptions() {
	s.client = fiber.New(
		fiber.Config{
			ErrorHandler: s.ErrorHandler,
			// We don't want active connections (Can be hijacked)
			DisableKeepalive: true,
		},
	)

	s.ServerOptions(
		requestid.New(),
		recover.New(),
		logger.New(),
	)
	if types.Cfg.Security.Ratelimiter {
		s.client.Use(limiter.New(limiter.Config{
			Max:               types.Cfg.Security.Ratelimit,
			Expiration:        time.Duration(types.Cfg.Security.RatelimitExp) * time.Second,
			LimiterMiddleware: limiter.SlidingWindow{},
		}))
	}
}

func (s *Server) IntegrityMiddleware(c fiber.Ctx, body []byte) error {
	byteRep := append(body, []byte(c.Route().Path)...)

	// We add the headers to the context, we need to alphabetize them first for predictability.
	keys, values := utils.Alphabetize(func() (r map[string]string) {
		r = make(map[string]string)
		for k, v := range c.GetRespHeaders() {
			if len(v) > 0 {
				r[k] = v[0]
			}
		}
		return
	}())

	byteRep = append(byteRep, utils.StringsToBytes(keys)...)
	byteRep = append(byteRep, utils.StringsToBytes(values)...)

	sessionID := c.Get("X-Session-Id")
	if sessionID == "" {
		return fiber.ErrUnauthorized
	}

	rawSession := make(fiber.Map)
	if err := s.rdb.HGetAll(s.dbCtx, sessionID, rawSession); err != nil {
		log.Error(log.GetStackTrace(), "Could not get session, Error: %v", err.Error())
		return fiber.ErrUnauthorized
	}
	session := FromMap(rawSession)

	signature := crypto.GenerateHMAC(byteRep, session.HashKey)
	c.Set("X-Signature", signature)
	return nil
}

func (s *Server) Bind() {
	jwtMiddleware := jwtware.New(jwtware.Config{
		SigningKey: jwtware.SigningKey{
			JWTAlg: jwtware.HS512,
			Key:    s.jwtSecret,
		},
		KeyFunc: func(t *jwt.Token) (interface{}, error) {
			if t.Method.Alg() != jwtware.HS512 {
				return nil, fmt.Errorf("unexpected jwt signing method=%v", t.Header["alg"])
			}
			return s.jwtSecret, nil
		},
		ErrorHandler: func(c fiber.Ctx, err error) error {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error(), "success": false})
		},
	})

	var Routes = [...]*Route{
		{
			Method:     "POST",
			Path:       "/license",
			Func:       s.VerifyLicense,
			Restricted: false,
		},
		{
			Method:     "POST",
			Path:       "/create-owner",
			Func:       s.NewOwner,
			Restricted: true,
		},
		{
			Method:     "POST",
			Path:       "/refresh",
			Func:       s.RefreshAccessToken,
			Restricted: false,
		},
		{
			Method:     "POST",
			Path:       "/login",
			Func:       s.Login,
			Restricted: false,
		},
		{
			Method:     "POST",
			Path:       "/logout",
			Func:       s.Logout,
			Restricted: true,
		},
		{
			Method:     "POST",
			Path:       "/register",
			Func:       s.Register,
			Restricted: false,
		},
		{
			Method:     "POST",
			Path:       "/create-application",
			Func:       s.CreateApplication,
			Restricted: true,
		},
		{
			Method:     "POST",
			Path:       "/create-license",
			Func:       s.CreateLicense,
			Restricted: true,
		},
	}

	for _, v := range Routes {
		log.Info("Binding -> %v [%v]", v.Path, v.Method)
		if v.Restricted {
			s.client.Add([]string{v.Method}, v.Path, v.Func, jwtMiddleware)
		} else {
			s.client.Add([]string{v.Method}, v.Path, v.Func)
		}
	}
}

func (s *Server) Start(port string) error {
	return s.client.Listen(":" + port)
}
