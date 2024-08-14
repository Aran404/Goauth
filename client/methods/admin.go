package sdk

import (
	"encoding/json"
	"errors"
	"fmt"
)

func (c *Client) CreateOwner(userID string) (string, error) {
	payload, err := json.Marshal(map[string]any{"user_id": userID})
	if err != nil {
		return "", err
	}

	resp := c.Request("POST", "/create-owner", payload, true, c.authHeaders())
	if resp.Error != nil {
		return "", resp.Error
	}

	if !resp.Ok {
		return "", fmt.Errorf("could not create owner, status code: %v, body: %v", resp.Status, string(resp.Body))
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
