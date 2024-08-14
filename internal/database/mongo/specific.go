package mongo

import (
	"encoding/json"
	"reflect"

	types "github.com/Aran404/Goauth/internal/types"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func ReadInto[T DataTypes](data []bson.M, v *T) error {
	if reflect.TypeOf(v).Kind() != reflect.Ptr {
		return types.ErrorNotPointer
	}

	raw, err := json.Marshal(data[0])
	if err != nil {
		return err
	}

	return json.Unmarshal(raw, v)
}

func CheckObjectArray(data *[]primitive.ObjectID, o primitive.ObjectID) bool {
	for _, v := range *data {
		if o == v {
			return true
		}
	}

	return false
}
