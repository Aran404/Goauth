package sdk

import (
	"encoding/json"
	"fmt"

	types "github.com/Aran404/goauth/Internal/Types"
)

func (c *Client) License(d *LicenseValidate) error {
	if d == nil {
		return types.ErrorEmptyStruct
	}

	body, err := json.Marshal(d)
	if err != nil {
		return err
	}

	response := c.Request("POST", "/license", body, true)
	if response.Error != nil {
		return response.Error
	}

	if !response.Ok {
		if v, ok := response.JSON["error"]; ok {
			return fmt.Errorf("could not validate license, status code: %v, error: %v", response.Status, v)
		}

		return fmt.Errorf("could not validate license, status code: %v, body: %v", response.Status, string(response.Body))
	}
	
	c.H.CloseIdleConnections()
	return ParseEncryptedResponse(response.JSON)
}
