package redis

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	types "github.com/Aran404/Goauth/internal/types"
)

func (c *Connection) Set(ctx context.Context, key string, value any, expiration time.Duration) error {
	return c.Client.Set(ctx, key, value, 0).Err()
}

func (c *Connection) HSet(ctx context.Context, key string, value any, expiration time.Duration) error {
	return c.Client.HSet(ctx, key, value, expiration).Err()
}

func (c *Connection) HGetAll(ctx context.Context, key string, vmap map[string]any) error {
	data, err := c.Client.HGetAll(ctx, key).Result()
	if err != nil {
		return err
	}

	raw := func() string {
		for k, _ := range data {
			return k
		}
		return ""
	}()

	if raw == "" {
		return types.ErrorEmptyStruct
	}

	var rawdata map[string]any
	if err := json.Unmarshal([]byte(raw), &rawdata); err != nil {
		return err
	}

	for k, v := range rawdata {
		decoded, err := base64.StdEncoding.DecodeString(v.(string))
		if err != nil {
			continue
		}

		vmap[k] = decoded
	}

	return nil
}

func (c *Connection) Delete(ctx context.Context, key string) error {
	return c.Client.Del(ctx, key).Err()
}

func (c *Connection) CheckTTL(ctx context.Context, key string) (time.Duration, error) {
	return c.Client.TTL(ctx, key).Result()
}

func (c *Connection) Exists(ctx context.Context, key string) (bool, error) {
	result, err := c.Client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}

	return result == 1, nil
}
