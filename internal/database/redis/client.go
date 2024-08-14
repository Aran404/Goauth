package redis

import (
	"context"
	"time"

	log "github.com/Aran404/Goauth/internal/logger"
	"github.com/redis/go-redis/v9"
)

type (
	Connection struct {
		Client *redis.Client
	}
)

func NewClient(ctx context.Context, host string) *Connection {
	now := time.Now()
	client := redis.NewClient(&redis.Options{
		Addr:     host,
		Password: "",
		DB:       0,
	})

	pong, err := client.Ping(ctx).Result()
	if err != nil {
		log.Fatal(log.GetStackTrace(), "Could not create redis client, Error: %v", err.Error())
	}

	log.Info("Connected to redis, Listener -> %v, Time Taken: %vs", pong, time.Since(now).Seconds())
	return &Connection{Client: client}
}
