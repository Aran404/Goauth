package utils

import (
	"encoding/base64"
	"fmt"
	"reflect"
)

func CheckEmptyFields(payload any, exceptions ...string) bool {
	r := reflect.ValueOf(payload)

	val := r.Elem()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)

		fieldName := val.Type().Field(i).Name
		if len(exceptions) > 0 && ArrayContains(exceptions, fieldName) {
			continue
		}

		if field.Kind() == reflect.String && field.String() == "" {
			return true
		}
	}

	return false
}

func ConvertToBase64(dest, structObj any) error {
	destVal := reflect.ValueOf(dest)
	if destVal.Kind() != reflect.Ptr || destVal.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("destination is not a pointer to a struct")
	}

	destElem := destVal.Elem()
	structVal := reflect.ValueOf(structObj)
	if structVal.Kind() == reflect.Ptr {
		structVal = structVal.Elem()
	}
	if structVal.Kind() != reflect.Struct {
		return fmt.Errorf("structObj is not a struct, type: %T", structObj)
	}

	t := structVal.Type()
	for i := 0; i < structVal.NumField(); i++ {
		field := t.Field(i)
		key := field.Name

		destField := destElem.FieldByName(key)
		if destField.IsValid() && destField.CanSet() {
			srcValue := structVal.Field(i)

			if srcValue.Kind() == reflect.Array || srcValue.Kind() == reflect.Slice {
				base64Str := base64.StdEncoding.EncodeToString(srcValue.Bytes())
				destField.SetString(base64Str)
			} else {
				destField.Set(srcValue)
			}
		}
	}

	return nil
}
