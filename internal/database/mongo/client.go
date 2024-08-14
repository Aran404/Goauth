package mongo

import (
	"context"
	"time"

	log "github.com/Aran404/Goauth/internal/logger"
	types "github.com/Aran404/Goauth/internal/types"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func NewConn(ctx context.Context) *Connection {
	options := options.Client().
		ApplyURI(types.Cfg.Mongo.Host).
		SetConnectTimeout(time.Duration(types.Cfg.Mongo.Timeout) * time.Second)

	client, err := mongo.Connect(ctx, options)
	if err != nil {
		log.Fatal(log.GetStackTrace(), "Could not create mongo client, Error: %v", err.Error())
	}

	log.Info("Connected to mongo, Listener -> %v", types.Cfg.Mongo.Host)
	start := time.Now()

	if err = client.Ping(ctx, nil); err != nil {
		log.Fatal(log.GetStackTrace(), "Could not ping client, Error: %v", err.Error())
	}

	log.Info("Pinged client in %vs", time.Since(start).Seconds())
	return &Connection{Client: client, Collections: make(map[string]*mongo.Collection)}
}

func (c *Connection) NewCollection(col string) *mongo.Collection {
	if _, ok := c.Collections[col]; ok {
		return c.Collections[col]
	}

	collection := c.Client.Database(types.Cfg.Mongo.Database).Collection(col)
	c.Collections[col] = collection
	return collection
}

// Get gets a collection in the database
func (c *Connection) Get(col string) *mongo.Collection {
	return c.NewCollection(col)
}

// Close closes the mongo connection
func (c *Connection) Close(ctx context.Context) {
	if err := c.Client.Disconnect(ctx); err != nil {
		log.Fatal(log.GetStackTrace(), "Could not close mongo client, Error: %v", err)
	}
}
