package server

import (
	"encoding/base64"
	"encoding/json"
	"time"

	crypto "github.com/Aran404/goauth/Internal/Crypto"
	log "github.com/Aran404/goauth/Internal/Logger"
	types "github.com/Aran404/goauth/Internal/Types"
	utils "github.com/Aran404/goauth/Internal/Utils"
	"github.com/dgrr/fastws"
	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/monnand/dhkx"
)

func (s *Server) ServeHello(conn *fastws.Conn) {
	log.Info("Started key exchange")
	if err := s.ClientHello(conn); err != nil {
		log.Error(log.GetStackTrace(), "Error initializing secure connection: %v", err)
	}
}

// ClientHello preforms a DHE and registers a new session if successful.
func (s *Server) ClientHello(conn *fastws.Conn) error {
	// Calculate DHE values
	group, err := dhkx.GetGroup(14)
	if err != nil {
		return err
	}

	priv, err := group.GeneratePrivateKey(nil)
	if err != nil {
		return err
	}

	c := &Connection{conn}

	pub := priv.Bytes()
	if err := c.SendHello(pub); err != nil {
		return err
	}

	otherPub, nonce, err := c.RecvHello()
	if err != nil {
		return err
	}

	decodedKey, err := base64.StdEncoding.DecodeString(*otherPub)
	if err != nil {
		return err
	}

	decodedNonce, err := base64.StdEncoding.DecodeString(*nonce)
	if err != nil {
		return err
	}

	hk, err := group.ComputeKey(dhkx.NewPublicKey(decodedKey), priv)
	if err != nil {
		return err
	}

	hashSeed := time.Now().Unix()
	derivedKey := ([32]byte)(hk.Bytes()[0:32])
	derivedNonce := ([12]byte)(decodedNonce)

	// End Key Exchange
	s.smutex.Lock()
	sessionID := uuid.NewString()

	var encoded SterlizedSession
	err = utils.ConvertToBase64(&encoded, &Session{
		PrivateKey: derivedKey,
		Nonce:      derivedNonce,
		HashKey:    crypto.DeriveKey(derivedKey, hashSeed),
	})
	if err != nil {
		s.smutex.Unlock()
		return err
	}

	raw, err := json.Marshal(encoded)
	if err != nil {
		s.smutex.Unlock()
		return err
	}

	if err := s.rdb.HSet(s.dbCtx, sessionID, raw, time.Duration(types.Cfg.DestroySession)*time.Second); err != nil {
		s.smutex.Unlock()
		return err
	}
	s.smutex.Unlock()

	log.Info("Successfully exchanged keys, Session ID: %v", sessionID)

	encodedSessionID, err := crypto.Encrypt([]byte(sessionID), derivedKey, derivedNonce)
	if err != nil {
		return err
	}

	if err := c.SendFinalAck(string(encodedSessionID), hashSeed); err != nil {
		return err
	}

	return nil
}

func (c *Connection) SendHello(payload []byte) error {
	staged, err := json.Marshal(fiber.Map{"public": payload})
	if err != nil {
		return err
	}

	_, err = c.WriteMessage(fastws.ModeBinary, staged)
	return err
}

func (c *Connection) RecvHello() (*string, *string, error) {
	var (
		payload []byte
		err     error
	)

	_, payload, err = c.ReadMessage(payload[:0])
	if err != nil {
		return nil, nil, err
	}

	if payload == nil {
		return nil, nil, types.ErrorInvalidHello
	}

	data, nonce, err := c.validateHelloPayload(payload)
	if err != nil {
		return nil, nil, err
	}

	if data == "" || nonce == "" {
		payload, err := json.Marshal(fiber.Map{"error": err.Error()})
		if err != nil {
			return nil, nil, err
		}

		if _, err = c.WriteMessage(fastws.ModeBinary, payload); err != nil {
			return nil, nil, err
		}

		return c.RecvHello()
	}

	return &data, &nonce, nil
}

func (c *Connection) validateHelloPayload(payload []byte) (publicKey string, nonce string, err error) {
	var data fiber.Map
	if err = json.Unmarshal(payload, &data); err != nil {
		err = types.ErrorInvalidJSON
		return
	}

	publicKey, ok := data["public"].(string)
	if !ok || len(publicKey) == 0 {
		err = types.ErrorInvalidHello
		return
	}

	nonce, ok = data["nonce"].(string)
	if !ok || len(nonce) == 0 {
		err = types.ErrorInvalidHello
	}

	return
}

func (c *Connection) SendFinalAck(sessionID string, hmacSeed int64) error {
	staged, err := json.Marshal(fiber.Map{"session_id": sessionID, "hmac_seed": hmacSeed})
	if err != nil {
		return err
	}

	_, err = c.WriteMessage(fastws.ModeBinary, staged)
	return err
}
