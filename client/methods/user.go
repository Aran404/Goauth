package sdk

import (
	"encoding/json"
	"errors"
	"fmt"

	types "github.com/Aran404/Goauth/internal/types"
)

func (c *Client) CreateApplication(name string) (string, error) {
	payload, err := json.Marshal(map[string]any{"owner_id": c.OwnerID, "name": name})
	if err != nil {
		return "", err
	}

	resp := c.Request("POST", "/create-application", payload, true, c.authHeaders())
	if resp.Error != nil {
		return "", resp.Error
	}

	if !resp.Ok {
		return "", fmt.Errorf("could not create application, status code: %v, body: %v", resp.Status, string(resp.Body))
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

func (c *Client) CreateLicense(settings *License) (string, error) {
	if settings == nil {
		return "", types.ErrorEmptyStruct
	}

	payload, err := json.Marshal(settings)
	if err != nil {
		return "", err
	}

	resp := c.Request("POST", "/create-license", payload, true, c.authHeaders())
	if resp.Error != nil {
		return "", resp.Error
	}

	if !resp.Ok {
		return "", fmt.Errorf("could not create license, status code: %v, body: %v", resp.Status, string(resp.Body))
	}

	if err := ParseEncryptedResponse(resp.JSON); err != nil {
		return "", err
	}

	license, ok := resp.JSON["key"].(string)
	if !ok {
		return "", errors.New("improper response from server")
	}

	return license, nil
}
