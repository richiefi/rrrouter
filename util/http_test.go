package util

import (
	"github.com/stretchr/testify/require"
	"net/http"
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
		origUrl, _ := url.Parse(test[0])
		orig := &http.Request{
			URL: origUrl,
		}
		redir, _ := url.Parse(test[1])
		expected := test[2]
		require.Equal(t, expected, RedirectedURL(orig, redir).String())
	}
}
