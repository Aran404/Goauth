package utils

import (
	"cmp"
	"slices"
)

func ArrayContains[T comparable](arr []T, item T) bool {
	for _, v := range arr {
		if v == item {
			return true
		}
	}
	return false
}

func Alphabetize[E cmp.Ordered](m map[string]E) ([]string, []E) {
	keys := make([]string, 0, len(m))
	values := make([]E, 0, len(m))

	for k, v := range m {
		keys = append(keys, k)
		values = append(values, v)
	}

	slices.Sort(keys)
	slices.Sort(values)
	return keys, values
}
