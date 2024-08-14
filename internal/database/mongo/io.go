package mongo

import (
	"context"
	"reflect"
	"strings"

	log "github.com/Aran404/Goauth/internal/logger"
	"github.com/Aran404/Goauth/internal/types"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// Create creates a new item in the collection
func (c *Connection) Create(ctx context.Context, coll string, data any) error {
	return c.Write(ctx, coll, data)
}

// CreateCreateAndReturn creates a new item in the collection and returns it
func (c *Connection) CreateAndReturn(ctx context.Context, coll string, data any) (*mongo.InsertOneResult, error) {
	return c.Get(coll).InsertOne(ctx, data)
}

// Write writes information to the collection
func (c *Connection) Write(ctx context.Context, name string, w any) error {
	coll := c.Get(name)
	_, err := coll.InsertOne(ctx, w)
	return err
}

// Update updates the collection based on a query
func (c *Connection) Update(ctx context.Context, name string, query, data any) error {
	coll := c.Get(name)
	update := bson.M{
		"$set": data,
	}

	_, err := coll.UpdateOne(ctx, query, update)
	return err
}

// Exists checks if a query matches in a collection
func (c *Connection) Exists(ctx context.Context, name string, query any) (bool, error) {
	coll := c.Get(name)

	count, err := coll.CountDocuments(ctx, query)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// CollectionExists checks if a collection exists
func (c *Connection) CollectionExists(ctx context.Context, name string) (bool, error) {
	db := c.Client.Database(types.Cfg.Mongo.Database)

	collections, err := db.ListCollectionNames(ctx, bson.D{{}})
	if err != nil {
		log.Fatal(log.GetStackTrace(), "Could not get all collections, Error: %v", err)
	}

	for _, v := range collections {
		if name == v {
			return true, nil
		}
	}

	return false, nil
}

// Read reads the information in a collection
func (c *Connection) Read(ctx context.Context, name string, v *[]bson.M) error {
	if reflect.TypeOf(v).Kind() != reflect.Ptr {
		return types.ErrorNotPointer
	}

	coll := c.Get(name)

	cursor, err := coll.Find(ctx, bson.D{{}})
	if err != nil {
		return err
	}

	return cursor.All(ctx, v)
}

// Filter looks for a match with the given search query
func (c *Connection) Filter(ctx context.Context, name string, query any, collisions bool, notFound ...error) ([]bson.M, error) {
	coll := c.Get(name)

	cursor, err := coll.Find(ctx, query)
	if err != nil {
		return nil, err
	}

	var Matched []bson.M
	if err := cursor.All(ctx, &Matched); err != nil {
		return nil, err
	}

	if len(Matched) <= 0 {
		if len(notFound) > 0 {
			return nil, notFound[0]
		}
		return nil, types.ErrorNotFound
	}

	if collisions && len(Matched) > 1 {
		return nil, types.ErrorCollision
	}

	return Matched, nil
}

// Delete deletes an item from the collection that matches the query
func (c *Connection) Delete(ctx context.Context, name string, query any) error {
	coll := c.Get(name)

	count, err := coll.DeleteMany(ctx, query)
	if count.DeletedCount <= 0 {
		return types.ErrorNoMatches
	}

	return err
}

// Drop drops the collection
func (c *Connection) Drop(ctx context.Context, name string) {
	if !types.ALLOW_DROPPING_COLLECTIONS {
		log.Fatal(log.GetStackTrace(), types.ErrorSafeSwitch.Error())
	}

	coll := c.Get(name)

	if err := coll.Drop(ctx); err != nil {
		log.Fatal(log.GetStackTrace(), "Could not drop collection. Collection Name: %v, Error: %v", name, err)
	}

	log.Info("Dropped -> %v", strings.ToUpper(name))
}

// DropAll drops all the collection
func (c *Connection) DropAll(ctx context.Context) {
	db := c.Client.Database(types.Cfg.Mongo.Database)

	collections, err := db.ListCollectionNames(ctx, bson.D{{}})
	if err != nil {
		log.Fatal(log.GetStackTrace(), "Could not get all collections, Error: %v", err)
	}

	for _, name := range collections {
		c.Drop(ctx, name)
	}
}
