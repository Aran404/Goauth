package mongo

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	Applications = "applications"
	Owners       = "owners"
	Licenses     = "licenses"
	Users        = "users"
)

type (
	Connection struct {
		Client      *mongo.Client
		Collections map[string]*mongo.Collection
	}

	ApplicationObject struct {
		ID                 primitive.ObjectID   `json:"_id,omitempty" bson:"_id,omitempty"`
		OwnerID            primitive.ObjectID   `json:"owner_id" bson:"owner_id"`
		Licenses           []primitive.ObjectID `json:"licenses" bson:"licenses"`
		IntegritySignature *string              `json:"integrity_signature" bson:"integrity_signature"`
		Name               string               `json:"name" bson:"name"`
	}

	OwnerObject struct {
		ID           primitive.ObjectID   `json:"_id" bson:"_id,omitempty"`
		Applications []primitive.ObjectID `json:"app_ids" bson:"app_ids"`
		User         primitive.ObjectID   `json:"user_id" bson:"user_id"`
	}

	LicenseObject struct {
		ID             primitive.ObjectID `json:"_id" bson:"_id,omitempty"`
		Application    primitive.ObjectID `json:"app_id" bson:"app_id"`
		OwnerID        primitive.ObjectID `json:"owner_id" bson:"owner_id"`
		Key            string             `json:"key" bson:"key"`
		Fingerprint    *string            `json:"fingerprint" bson:"fingerprint"`
		ExpectedExpiry uint64             `json:"expected_expiry" bson:"expected_expiry"`
		Expiry         *uint64            `json:"expiry" bson:"expiry"`
	}

	UserObject struct {
		ID           primitive.ObjectID `json:"_id" bson:"_id,omitempty"`
		Admin        int8               `json:"admin" bson:"admin"`
		RefreshToken string             `json:"refresh_token" bson:"refresh_token"`
		Username     string             `json:"username" bson:"username"`
		Password     string             `json:"password" bson:"password"`
	}

	DataTypes interface {
		ApplicationObject | OwnerObject | LicenseObject | UserObject
	}
)
