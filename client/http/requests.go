package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	crypto "github.com/Aran404/Goauth/internal/crypto"
	log "github.com/Aran404/Goauth/internal/logger"
	types "github.com/Aran404/Goauth/internal/types"
	utils "github.com/Aran404/Goauth/internal/utils"
)

func (c *Client) Request(method, url string, input []byte, encrypted bool, m ...http.Header) *Response {
	r := new(Response)
	req, err := http.NewRequest(method, fmt.Sprint(c.Host, url), nil)
	if err != nil {
		r.Error = err
		return r
	}

	if len(m) > 0 {
		req.Header = m[0]
	}

	if encrypted {
		input, err = c.encryptInput(input)
		if err != nil {
			r.Error = err
			return r
		}
		req.Header.Add("X-Session-ID", c.SessionID)
	}

	if input != nil && len(input) > 0 {
		req.Body = io.NopCloser(bytes.NewBuffer(input))
	}

	resp, err := c.H.Do(req)
	if err != nil {
		r.Error = err
		return r
	}

	return c.processResponse(resp, req, encrypted)
}

func (c *Client) encryptInput(input []byte) ([]byte, error) {
	encoded, err := crypto.Encrypt(input, c.P, c.Nonce)
	if err != nil {
		return nil, err
	}
	return []byte(encoded), nil
}

func (c *Client) processResponse(resp *http.Response, req *http.Request, encrypted bool) *Response {
	r := new(Response)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		r.Error = err
		return r
	}
	defer resp.Body.Close()

	if len(body) > 0 && string(body)[0] == byte('{') {
		return c.createResponse(resp, body, 1)
	}

	encodedBody := body[:]
	sig := resp.Header.Get("X-Signature")

	cleanupHeaders(resp)

	body = c.prepareBodyForHMAC(body, req, resp)
	sign := c.verifySignature(body, sig)

	if sign != -1 && !encrypted {
		if err := parseSign(sign); err != nil {
			r.Error = err
			return r
		}
	}

	if encrypted {
		body, err = c.decryptBody(encodedBody)
		if err != nil {
			r.Error = err
			return r
		}
	}

	return c.createResponse(resp, body, sign)
}

func parseSign(sign int8) error {
	switch sign {
	case -1:
		return types.ErrorNoIntegrity
	case 0:
		return types.ErrorInvalidIntegrity
	case 1:
		log.Info("Integrity verified. Proceeding with check...")
	}
	return nil
}

func cleanupHeaders(resp *http.Response) {
	for _, v := range [...]string{"Content-Length", "Date", "X-Signature"} {
		resp.Header.Del(v)
	}
}

func (c *Client) prepareBodyForHMAC(body []byte, req *http.Request, resp *http.Response) []byte {
	body = append(body, []byte(req.URL.Path)...)

	keys, values := utils.Alphabetize(func() map[string]string {
		r := make(map[string]string)
		for k, v := range resp.Header {
			if len(v) > 0 {
				r[k] = v[0]
			}
		}
		return r
	}())

	body = append(body, utils.StringsToBytes(keys)...)
	body = append(body, utils.StringsToBytes(values)...)

	return body
}

func (c *Client) verifySignature(body []byte, sig string) int8 {
	if sig != "" {
		real := crypto.GenerateHMAC(body, c.HashKey)
		return utils.Btoi(crypto.VerifyHMAC([]byte(sig), []byte(real)))
	}
	return -1
}

func (c *Client) decryptBody(encodedBody []byte) ([]byte, error) {
	decoded, err := crypto.Decrypt(string(encodedBody), c.P, c.Nonce)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func (c *Client) createResponse(resp *http.Response, body []byte, sign int8) *Response {
	r := &Response{
		Raw:    resp,
		Status: resp.StatusCode,
		Body:   body,
		Ok:     resp.StatusCode == 200,
		Signed: sign,
	}

	json.Unmarshal(body, &r.JSON)
	return r
}
