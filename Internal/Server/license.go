package server

import (
	"encoding/json"
	"time"

	mongo "github.com/Aran404/goauth/Internal/Database/Mongo"
	types "github.com/Aran404/goauth/Internal/Types"
	utils "github.com/Aran404/goauth/Internal/Utils"
	"github.com/gofiber/fiber/v3"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// VerifyLicense will verify the license against the database.
// We use Session based authentication instead of JWT because this should be treated as a one-time-use token.
// There will be no need to do anything after this process.
// If you would like to verify a license another time, it is much more secure to just create another session instead.
func (s *Server) VerifyLicense(c fiber.Ctx) error {
	session, raw, err := s.ParseBody(c)
	if err != nil {
		return err
	}

	holder, err := s.collectHolders(raw)
	if err != nil {
		return err
	}

	if err := s.validateFields(holder.msg, holder.license, holder.app); err != nil {
		return err
	}

	plainText := fiber.Map{
		"success": true,
		"context": uint64(time.Now().Unix()) + types.Cfg.Security.AllowedContext,
	}

	return s.EncryptJson(c, plainText, session)
}

func (s *Server) updateLicense(l *mongo.LicenseObject) error {
	return s.db.Update(s.dbCtx, mongo.Licenses, bson.M{"_id": l.ID}, l)
}

func (s *Server) updateApplication(l *mongo.ApplicationObject) error {
	return s.db.Update(s.dbCtx, mongo.Applications, bson.M{"_id": l.ID}, l)
}

// Verify the licenses validity
func (s *Server) validateFields(msg *LicenseMsg, l *mongo.LicenseObject, app *mongo.ApplicationObject) error {
	licenseCheck := false
	appCheck := false

	// The license is being used for the first time
	if l.Expiry == nil {
		licenseCheck = true
		period := uint64(time.Now().Unix()) + l.ExpectedExpiry
		l.Expiry = &period
	}

	if l.Fingerprint == nil {
		licenseCheck = true
		l.Fingerprint = &msg.Fingerprint
	}

	if app.IntegritySignature == nil {
		appCheck = true
		app.IntegritySignature = &msg.IntegritySignature
	}

	if licenseCheck {
		if err := s.updateLicense(l); err != nil {
			return err
		}
	}

	if appCheck {
		if err := s.updateApplication(app); err != nil {
			return err
		}
	}

	if msg.Fingerprint != *l.Fingerprint {
		return types.ErrorInvalidFingerprint
	}

	if msg.IntegritySignature != *app.IntegritySignature {
		return types.ErrorInvalidFingerprint
	}

	if uint64(time.Now().Unix()) > *l.Expiry {
		return types.ErrorExpiredLicense
	}

	return nil
}

// ? Maybe this function is doing too much
func (s *Server) collectHolders(body []byte) (*LicenseHolders, error) {
	var License *LicenseMsg
	if err := json.Unmarshal(body, &License); err != nil {
		return nil, types.ErrorInvalidJSON
	}

	if utils.CheckEmptyFields(License) {
		return nil, types.ErrorEmptyFields
	}

	owner, err := s.getOwner(License)
	if err != nil {
		return nil, err
	}

	application, err := s.getApplication(License, owner)
	if err != nil {
		return nil, err
	}

	proper, err := s.getLicense(License)
	if err != nil {
		return nil, err
	}

	return &LicenseHolders{License, proper, application}, nil
}

func (s *Server) getApplication(l *LicenseMsg, owner *mongo.OwnerObject) (*mongo.ApplicationObject, error) {
	// Verify AppID
	appID, err := primitive.ObjectIDFromHex(l.AppID)
	if err != nil {
		return nil, types.ErrorInvalidApp
	}

	if !mongo.CheckObjectArray(&owner.Applications, appID) {
		return nil, types.ErrorInvalidApp
	}

	appObj, err := s.db.Filter(s.dbCtx, mongo.Applications, bson.M{"_id": appID}, false, types.ErrorInvalidApp)
	if err != nil {
		return nil, err
	}

	var application mongo.ApplicationObject
	if err := mongo.ReadInto[mongo.ApplicationObject](appObj, &application); err != nil {
		return nil, err
	}

	return &application, nil
}

func (s *Server) getOwner(l *LicenseMsg) (*mongo.OwnerObject, error) {
	// Verify OwnerID
	ownerID, err := primitive.ObjectIDFromHex(l.OwnerID)
	if err != nil {
		return nil, types.ErrorInvalidOwner
	}

	ownerObj, err := s.db.Filter(s.dbCtx, mongo.Owners, bson.M{"_id": ownerID}, false, types.ErrorInvalidOwner)
	if err != nil {
		return nil, err
	}

	var owner mongo.OwnerObject
	if err := mongo.ReadInto[mongo.OwnerObject](ownerObj, &owner); err != nil {
		return nil, err
	}

	return &owner, nil
}

func (s *Server) getLicense(l *LicenseMsg) (*mongo.LicenseObject, error) {
	// Verify License
	licenseObj, err := s.db.Filter(s.dbCtx, mongo.Licenses, bson.M{"key": l.LicenseKey}, false, types.ErrorInvalidLicense)
	if err != nil {
		return nil, err
	}

	var license mongo.LicenseObject
	if err := mongo.ReadInto[mongo.LicenseObject](licenseObj, &license); err != nil {
		return nil, err
	}

	return &license, nil
}
