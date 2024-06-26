package websocket

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	crypto "github.com/Aran404/goauth/Internal/Crypto"
	types "github.com/Aran404/goauth/Internal/Types"
	"github.com/dgrr/fastws"
	"github.com/monnand/dhkx"
)

// ClientHello preforms a DHE.
// The private key is encoded in base64 and is 256 bits long (Before encoding)
func (c *Client) ClientHello() (*string, error) {
	nonce, err := crypto.GenerateNonce()
	if err != nil {
		return nil, err
	}
	c.Nonce = *nonce

	group, err := dhkx.GetGroup(14)
	if err != nil {
		return nil, err
	}

	priv, err := group.GeneratePrivateKey(nil)
	if err != nil {
		return nil, err
	}

	pub := priv.Bytes()
	if err := c.SendHello(pub, c.Nonce); err != nil {
		return nil, err
	}

	resp, err := c.RecvHello(c.validateHelloPayload)
	if err != nil {
		return nil, err
	}

	decodedKey, err := base64.StdEncoding.DecodeString(*resp)
	if err != nil {
		return nil, err
	}

	hk, err := group.ComputeKey(dhkx.NewPublicKey(decodedKey), priv)
	if err != nil {
		return nil, err
	}

	b := hk.Bytes()[0:32]
	c.P = ([32]byte)(b)

	// Clear all the memory for security
	b = nil
	hk = nil
	priv = nil
	pub = nil
	decodedKey = nil

	encoded := base64.StdEncoding.EncodeToString(b)
	return &encoded, nil
}

// RetrieveSession retrieves the session ID provided by the server
// The session ID is vital for all future requests
func (c *Client) RetrieveSession() (*string, error) {
	validate := func(b []byte) (string, error) {
		var data map[string]any
		if err := json.Unmarshal(b, &data); err != nil {
			return "", err
		}

		session, ok := data["session_id"].(string)
		if !ok {
			return "", types.ErrorInvalidHello
		}

		hmacSeed, ok := data["hmac_seed"].(float64)
		if !ok {
			return "", types.ErrorInvalidHello
		}

		return fmt.Sprintf("%s:%v", session, int64(hmacSeed)), nil
	}

	resp, err := c.RecvHello(validate)
	if err != nil {
		return nil, err
	}

	session := strings.Split((*resp), ":")[0]
	hmacSeed := strings.Split((*resp), ":")[1]

	i, err := strconv.Atoi(hmacSeed)
	if err != nil {
		return nil, err
	}

	// We only check request signature after the session has been established.
	c.HashKey = crypto.DeriveKey(c.P, int64(i))

	decrypted, err := crypto.Decrypt(session, c.P, c.Nonce)
	if err != nil {
		return nil, err
	}

	temp := string(decrypted)
	c.SessionID = temp

	return &temp, nil
}

func (c *Client) SendHello(pub []byte, nonce [12]byte) error {
	staged, err := json.Marshal(map[string]any{"public": pub, "nonce": base64.StdEncoding.EncodeToString(nonce[:])})
	if err != nil {
		return err
	}

	_, err = c.WriteMessage(fastws.ModeBinary, staged)
	return err
}

func (c *Client) RecvHello(validate func([]byte) (string, error)) (*string, error) {
	fr, err := c.NextFrame()
	if err != nil {
		return nil, err
	}

	payload := fr.Payload()
	if payload == nil {
		return nil, types.ErrorInvalidHello
	}

	data, err := validate(payload)
	if err != nil {
		return nil, err
	}

	if data == "" {
		errorPayload, err := json.Marshal(map[string]any{"error": err.Error()})
		if err != nil {
			return nil, err
		}

		if _, err = c.WriteMessage(fastws.ModeBinary, errorPayload); err != nil {
			return nil, err
		}

		return c.RecvHello(validate)
	}

	return &data, nil
}

func (c *Client) validateHelloPayload(b []byte) (string, error) {
	var data map[string]any
	if err := json.Unmarshal(b, &data); err != nil {
		return "", err
	}

	publicKey, ok := data["public"].(string)
	if !ok || len(publicKey) == 0 {
		return "", types.ErrorInvalidHello
	}

	return publicKey, nil
}
