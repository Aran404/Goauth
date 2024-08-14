package server

import (
	"encoding/json"
	"os"
	"time"

	crypto "github.com/Aran404/Goauth/internal/crypto"
	mongo "github.com/Aran404/Goauth/internal/database/mongo"
	types "github.com/Aran404/Goauth/internal/types"
	utils "github.com/Aran404/Goauth/internal/utils"
	"github.com/gofiber/fiber/v3"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func (s *Server) registerBody(body []byte) (*UserMsg, int8, error) {
	var (
		data    *UserMsg
		isAdmin bool
	)

	if err := json.Unmarshal(body, &data); err != nil {
		return nil, -1, types.ErrorInvalidJSON
	}

	if utils.CheckEmptyFields(data, "APIKey") {
		return nil, -1, types.ErrorEmptyFields
	}

	// Only owners can register admins
	realApiKey := os.Getenv("API_KEY")
	isAdmin = data.APIKey == realApiKey

	// Verify Password
	if !utils.CheckPassword(data.Password) {
		return nil, -1, types.ErrorInsecurePassword
	}

	if len(data.Username) < 3 || len(data.Username) > 20 {
		return nil, -1, types.ErrorIncorrectLength
	}

	// Make sure account doesn't already exist
	exists, err := s.db.Exists(s.dbCtx, mongo.Users, bson.M{"username": data.Username})
	if err != nil {
		return nil, -1, err
	}

	if exists {
		return nil, -1, types.ErrorAccountExists
	}

	return data, utils.Btoi(isAdmin), nil
}

func (s *Server) finalizeRegister(c fiber.Ctx, admin int8, msg *UserMsg, session *Session) error {
	dump := &mongo.UserObject{
		Username: msg.Username,
		Admin:    admin,
	}

	hashed, err := crypto.HashPassword(msg.Password)
	if err != nil {
		return err
	}
	dump.Password = hashed

	id, err := s.db.CreateAndReturn(s.dbCtx, mongo.Users, dump)
	if err != nil {
		return err
	}

	returnDump := fiber.Map{"success": true, "id": id.InsertedID.(primitive.ObjectID).Hex(), "context": time.Now().Unix() + int64(types.Cfg.Security.AllowedContext)}
	return s.EncryptJson(c, returnDump, session)
}

func (s *Server) parseLoginBody(body []byte) (*mongo.UserObject, error) {
	var data *UserMsg
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, types.ErrorInvalidJSON
	}

	if utils.CheckEmptyFields(data, "APIKey") {
		return nil, types.ErrorEmptyFields
	}

	dump, err := s.db.Filter(s.dbCtx, mongo.Users, bson.M{"username": data.Username}, false, types.ErrorUserNotFound)
	if err != nil {
		return nil, err
	}

	var user mongo.UserObject
	if err := mongo.ReadInto[mongo.UserObject](dump, &user); err != nil {
		return nil, err
	}

	if !crypto.CheckPasswordHash(data.Password, user.Password) {
		return nil, types.ErrorIncorrectPassword
	}

	return &user, nil
}

// Login will authenticate an account via JWT
func (s *Server) Login(c fiber.Ctx) error {
	session, body, err := s.ParseBody(c)
	if err != nil {
		return err
	}

	data, err := s.parseLoginBody(body)
	if err != nil {
		return err
	}

	resp, err := s.GenerateKeyPair(data.Username, data.Admin)
	if err != nil {
		return err
	}

	updatePayload := bson.M{"refresh_token": (*resp)["refresh_token"].(string)}
	if err := s.db.Update(s.dbCtx, mongo.Users, bson.M{"username": data.Username}, updatePayload); err != nil {
		return err
	}

	return s.EncryptJson(c, *resp, session)
}

// Register will create a new account
func (s *Server) Register(c fiber.Ctx) error {
	session, body, err := s.ParseBody(c)
	if err != nil {
		return err
	}

	msg, admin, err := s.registerBody(body)
	if err != nil {
		return err
	}

	return s.finalizeRegister(c, admin, msg, session)
}

// Logout will delete the refresh token from the database
func (s *Server) Logout(c fiber.Ctx) error {
	refreshToken := c.Cookies("refresh_token")
	if refreshToken == "" {
		return types.ErrorNoRefreshToken
	}

	return s.db.Update(s.dbCtx, mongo.Users, bson.M{"refresh_token": refreshToken}, bson.M{"refresh_token": ""})
}

// ! Probably won't do these anytime soon unless the project picks up some traction
// TODO: Delete account
// TODO: Change password
// TODO: Change username
