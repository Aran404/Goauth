package server

import (
	"encoding/json"
	"time"

	mongo "github.com/Aran404/Goauth/internal/database/mongo"
	types "github.com/Aran404/Goauth/internal/types"
	"github.com/gofiber/fiber/v3"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Admin only route
func (s *Server) NewOwner(c fiber.Ctx) error {
	session, body, err := s.ParseBody(c)
	if err != nil {
		return err
	}

	msg, err := s.parseJWTFields(c)
	if err != nil {
		return err
	}

	if time.Now().Unix() > int64(msg.Exp) || msg.Admin != 1 {
		return c.SendStatus(fiber.StatusUnauthorized)
	}

	userID, err := s.parseNewOwnerBody(body)
	if err != nil {
		return err
	}

	// ID will be auto-assigned
	payload := &mongo.OwnerObject{Applications: []primitive.ObjectID{}, User: *userID}
	item, err := s.db.CreateAndReturn(s.dbCtx, mongo.Owners, payload)
	if err != nil {
		return err
	}

	id, ok := item.InsertedID.(primitive.ObjectID)
	if !ok {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	returnDump := fiber.Map{"success": true, "id": id.Hex(), "context": time.Now().Unix() + int64(types.Cfg.Security.AllowedContext)}
	return s.EncryptJson(c, returnDump, session)
}

func (s *Server) parseNewOwnerBody(body []byte) (*primitive.ObjectID, error) {
	var msg fiber.Map
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, types.ErrorInvalidJSON
	}

	id, ok := msg["user_id"].(string)
	if !ok {
		return nil, types.ErrorEmptyFields
	}

	proper, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, types.ErrorInvalidUserID
	}

	exists, err := s.db.Exists(s.dbCtx, mongo.Users, bson.M{"_id": proper})
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, types.ErrorInvalidUserID
	}

	return &proper, nil
}

// ! Probably won't do these anytime soon unless the project picks some traction
// TODO: Delete owner
// TODO: Delete Specific Application
// TODO: Expiry On Account
