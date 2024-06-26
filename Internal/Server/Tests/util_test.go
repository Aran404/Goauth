package tests

import (
	"fmt"
	"testing"

	utils "github.com/Aran404/goauth/Internal/Utils"
)

func TestCheckEmptyFields(t *testing.T) {
	type TestStruct struct {
		Field1 string
		Field2 string
		Field3 string
	}

	cases := []struct {
		payload    interface{}
		exceptions []string
		expect     bool
	}{
		{
			payload: &TestStruct{
				Field1: "",
				Field2: "",
				Field3: "",
			},
			exceptions: []string{},
			expect:     true,
		},
		{
			payload: &TestStruct{
				Field1: "test",
				Field2: "",
				Field3: "",
			},
			exceptions: []string{},
			expect:     true,
		},
		{
			payload: &TestStruct{
				Field1: "test",
				Field2: "test",
				Field3: "",
			},
			exceptions: []string{},
			expect:     true,
		},
		{
			payload: &TestStruct{
				Field1: "test",
				Field2: "test",
				Field3: "test",
			},
			exceptions: []string{},
			expect:     false,
		},
		{
			payload: &TestStruct{
				Field1: "",
				Field2: "",
				Field3: "",
			},
			exceptions: []string{"Field1", "Field2", "Field3"},
			expect:     false,
		},
		{
			payload: &TestStruct{
				Field1: "",
				Field2: "",
				Field3: "",
			},
			exceptions: []string{"Field1", "Field2"},
			expect:     true,
		},
	}

	for i, c := range cases {
		result := utils.CheckEmptyFields(c.payload, c.exceptions...)
		if result != c.expect {
			t.Errorf("Test case failed: %#v", i+1)
		}
	}
}

// TestCreateLicense tests the CreateLicense function.
func TestCreateLicense(t *testing.T) {
	masks := []string{
		"",
		"test",
		"test-****-****-****-****",
		"test-1234-****-****-****",
		"test-1234-1234-****-****",
		"test-1234-1234-1234-****",
		"test-1234-1234-1234-1234",
	}

	// Test cases without any settings
	for _, v := range masks {
		t.Run(fmt.Sprintf("Mask: %s", v), func(t *testing.T) {
			license := utils.CreateLicense(utils.LicenseSettings{
				Mask: v,
			})
			t.Logf("Generated License: %s", license)
		})
	}

	// Test cases with OnlyCapitals set to true
	for _, v := range masks {
		t.Run(fmt.Sprintf("Mask: %s, OnlyCapitals: true", v), func(t *testing.T) {
			license := utils.CreateLicense(utils.LicenseSettings{
				Mask:         v,
				OnlyCapitals: true,
			})
			t.Logf("Generated License (OnlyCapitals): %s", license)
		})
	}

	// Test cases with OnlyLowercase set to true
	for _, v := range masks {
		t.Run(fmt.Sprintf("Mask: %s, OnlyLowercase: true", v), func(t *testing.T) {
			license := utils.CreateLicense(utils.LicenseSettings{
				Mask:          v,
				OnlyLowercase: true,
			})
			t.Logf("Generated License (OnlyLowercase): %s", license)
		})
	}
}
