package sdk

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/mitchellh/mapstructure"
)

func (c *Client) Register(username, password string, apiKey ...string) (string, error) {
	var raw = map[string]any{"username": username, "password": password}
	if len(apiKey) > 0 {
		raw["api_key"] = apiKey[0]
	}

	payload, err := json.Marshal(raw)
	if err != nil {
		return "", err
	}

	resp := c.Request("POST", "/register", payload, true)
	if resp.Error != nil {
		return "", resp.Error
	}

	if !resp.Ok {
		return "", fmt.Errorf("could not register user, status code: %v, body: %v", resp.Status, string(resp.Body))
	}

	if err := ParseEncryptedResponse(resp.JSON); err != nil {
		return "", err
	}

	id, ok := resp.JSON["id"].(string)
	if !ok {
		return "", errors.New("improper response from server")
	}

	return id, nil
}

func (c *Client) Login(username, password string) (*LoginInfo, error) {
	payload, err := json.Marshal(map[string]any{"username": username, "password": password})
	if err != nil {
		return nil, err
	}

	resp := c.Request("POST", "/login", payload, true)
	if resp.Error != nil {
		return nil, resp.Error
	}

	if !resp.Ok {
		return nil, fmt.Errorf("could not login, status code: %v, body: %v", resp.Status, string(resp.Body))
	}

	if err := ParseEncryptedResponse(resp.JSON); err != nil {
		return nil, err
	}

	var data LoginInfo
	if err := mapstructure.Decode(resp.JSON, &data); err != nil {
		return nil, err
	}

	c.auth = &data
	return c.auth, nil
}

func (c *Client) Logout() error {
	resp := c.Request("POST", "/logout", nil, true, c.authHeaders())
	if resp.Error != nil {
		return resp.Error
	}

	if !resp.Ok {
		return fmt.Errorf("could not logout, status code: %v, body: %v", resp.Status, string(resp.Body))
	}

	return ParseEncryptedResponse(resp.JSON)
}

func (c *Client) authHeaders() http.Header {
	return http.Header{
		"Authorization": []string{fmt.Sprintf("Bearer %s", c.auth.Token)},
		"Cookie":        []string{fmt.Sprint("refresh_token=", c.auth.RefreshToken)},
	}
}
