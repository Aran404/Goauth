package server

import (
	"encoding/json"
	"time"

	mongo "github.com/Aran404/Goauth/internal/database/mongo"
	types "github.com/Aran404/Goauth/internal/types"
	utils "github.com/Aran404/Goauth/internal/utils"
	"github.com/gofiber/fiber/v3"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func (s *Server) parseCreateAppBody(body []byte) (*mongo.OwnerObject, *NewApplicationMsg, error) {
	var msg *NewApplicationMsg
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, nil, err
	}

	if utils.CheckEmptyFields(msg) {
		return nil, nil, types.ErrorEmptyFields
	}

	items, err := s.verifyAppInDatabase(msg)
	if err != nil {
		return nil, nil, err
	}

	var owner mongo.OwnerObject
	if err := mongo.ReadInto[mongo.OwnerObject](*items, &owner); err != nil {
		return nil, nil, err
	}

	return &owner, msg, nil
}

func (s *Server) verifyAppInDatabase(msg *NewApplicationMsg, _id ...string) (*[]primitive.M, error) {
	ownerID, err := primitive.ObjectIDFromHex(msg.OwnerID)
	if err != nil {
		return nil, types.ErrorInvalidOwner
	}

	items, err := s.db.Filter(s.dbCtx, mongo.Owners, bson.M{"_id": ownerID}, false, types.ErrorInvalidOwner)
	if err != nil {
		return nil, err
	}

	dump := bson.M{"name": msg.Name, "owner_id": ownerID}
	if len(_id) > 0 {
		dump["_id"] = _id[0]
	}

	// Make sure app doesn't already exist (if len(_id) == 0)
	exists, err := s.db.Exists(s.dbCtx, mongo.Applications, dump)
	if err != nil {
		return nil, err
	}

	if exists && len(_id) == 0 {
		return nil, types.ErrorApplicationExists
	}

	return &items, nil
}

func (s *Server) finalizeCreateApp(msg *NewApplicationMsg, owner *mongo.OwnerObject) (string, error) {
	dump := &mongo.ApplicationObject{
		Name:     msg.Name,
		OwnerID:  owner.ID,
		Licenses: []primitive.ObjectID{},
	}
	id, err := s.db.CreateAndReturn(s.dbCtx, mongo.Applications, dump)
	if err != nil {
		return "", err
	}

	proper := id.InsertedID.(primitive.ObjectID)
	owner.Applications = append(owner.Applications, proper)
	return proper.Hex(), s.db.Update(s.dbCtx, mongo.Owners, bson.M{"_id": owner.ID}, owner)
}

func (s *Server) parseCreateLicenseBody(body []byte) (*NewLicenseMsg, *[]primitive.M, error) {
	var msg *NewLicenseMsg
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, nil, err
	}

	if utils.CheckEmptyFields(msg, "Mask") {
		return nil, nil, types.ErrorEmptyFields
	}

	owner, err := s.verifyAppInDatabase(&NewApplicationMsg{
		OwnerID: msg.OwnerID,
		Name:    msg.AppName,
	}, msg.AppID)
	if err != nil {
		return nil, nil, err
	}

	return msg, owner, nil
}

func (s *Server) verifyUser(c fiber.Ctx, owner *mongo.OwnerObject) error {
	fields, err := s.parseJWTFields(c)
	if err != nil {
		return err
	}

	if time.Now().Unix() > int64(fields.Exp) {
		return fiber.ErrUnauthorized
	}

	unparsed, err := s.db.Filter(s.dbCtx, mongo.Users, bson.M{"username": fields.Username}, false, types.ErrorUserNotFound)
	if err != nil {
		return err
	}

	var user mongo.UserObject
	if err := mongo.ReadInto[mongo.UserObject](unparsed, &user); err != nil {
		return err
	}

	if user.ID != owner.User {
		return fiber.ErrUnauthorized
	}

	return nil
}

func (s *Server) dumpLicense(l *mongo.LicenseObject, appID string) error {
	properID, err := primitive.ObjectIDFromHex(appID)
	if err != nil {
		return err
	}

	app, err := s.db.Filter(s.dbCtx, mongo.Applications, bson.M{"_id": properID}, false, types.ErrorInvalidApp)
	if err != nil {
		return err
	}

	var application mongo.ApplicationObject
	if err := mongo.ReadInto[mongo.ApplicationObject](app, &application); err != nil {
		return err
	}
	l.Application = application.ID

	item, err := s.db.CreateAndReturn(s.dbCtx, mongo.Licenses, l)
	if err != nil {
		return err
	}

	id, ok := item.InsertedID.(primitive.ObjectID)
	if !ok {
		return fiber.ErrInternalServerError
	}

	application.Licenses = append(application.Licenses, id)
	return s.updateApplication(&application)
}

// CreateApplication creates a new application and dumps it in the database
// ! Most of these endpoints don't need to be encrypted.
// * If it's ever going to be used in production, it's probably a good idea to remove the encryption.
func (s *Server) CreateApplication(c fiber.Ctx) error {
	session, body, err := s.ParseBody(c)
	if err != nil {
		return err
	}

	owner, msg, err := s.parseCreateAppBody(body)
	if err != nil {
		return err
	}

	id, err := s.finalizeCreateApp(msg, owner)
	if err != nil {
		return err
	}

	returnDump := fiber.Map{"success": true, "id": id, "context": time.Now().Unix() + int64(types.Cfg.Security.AllowedContext)}
	return s.EncryptJson(c, returnDump, session)
}

// CreateLicense creates a new license and dumps it in the database
func (s *Server) CreateLicense(c fiber.Ctx) error {
	session, body, err := s.ParseBody(c)
	if err != nil {
		return err
	}

	msg, unparsed, err := s.parseCreateLicenseBody(body)
	if err != nil {
		return err
	}

	var owner mongo.OwnerObject
	if err := mongo.ReadInto[mongo.OwnerObject](*unparsed, &owner); err != nil {
		return err
	}

	// Now we must check if the request is authorized to do this action
	if err := s.verifyUser(c, &owner); err != nil {
		return err
	}

	licenseString := utils.CreateLicense(utils.LicenseSettings{
		Mask:          msg.Mask,
		OnlyCapitals:  msg.OnlyCapitals,
		OnlyLowercase: msg.OnlyLowercase,
	})
	license := &mongo.LicenseObject{
		Key:            licenseString,
		OwnerID:        owner.ID,
		ExpectedExpiry: msg.Expiry,
	}

	// ! In production you must use a mutex to prevent data races
	if err := s.dumpLicense(license, msg.AppID); err != nil {
		return err
	}

	returnDump := fiber.Map{"success": true, "key": licenseString, "context": time.Now().Unix() + int64(types.Cfg.Security.AllowedContext)}
	return s.EncryptJson(c, returnDump, session)
}

// ! Probably won't do these anytime soon unless the project picks up some traction
// TODO: Delete application
// TODO: Delete specific license
