package util

import (
	"github.com/stretchr/testify/require"
	"net/url"
	"testing"
)

func TestRedirectedURL(t *testing.T) {
	tests := [][]string{
		{"https://example.com/", "https://example.com/1?a=b", "https://example.com/1?a=b"},
		{"https://example.com/", "/1?a=b", "https://example.com/1?a=b"},
		{"https://example.com/", "1?a=b", "https://example.com/1?a=b"},
		{"https://example.com/1?a=b", "2?b=c", "https://example.com/2?b=c"},
	}
	for _, test := range tests {
		orig, _ := url.Parse(test[0])
		redir, _ := url.Parse(test[1])
		expected := test[2]
		require.Equal(t, expected, RedirectedURL(orig, redir).String())
	}
}
