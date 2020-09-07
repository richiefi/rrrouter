package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStringInSlice(t *testing.T) {
	tests := []struct {
		inputSlice  []string
		inputString string
		expect      bool
	}{
		{[]string{}, "", false},
		{[]string{"a"}, "", false},
		{[]string{"a"}, "a", true},
		{[]string{"a", "b", "c"}, "", false},
		{[]string{"a", "b", "c"}, "a", true},
		{[]string{"a", "b", "c"}, "b", true},
		{[]string{"a", "b", "c"}, "c", true},
	}
	for _, test := range tests {
		require.Equal(t, StringInSlice(test.inputSlice, test.inputString), test.expect, test.inputSlice, test.inputString)
	}
}
