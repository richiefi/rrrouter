package util

import (
	"github.com/stretchr/testify/require"
	"net/http"
	"net/url"
	"os"
	"testing"
)

func TestRedirectedURL(t *testing.T) {
	tests := [][]string{
		{"https://edge.example.com/", "https://inner.example.com/a", "https://example.com/1?a=b", "https://example.com/1?a=b"},
		{"https://edge.example.com/", "https://inner.example.com/a", "/1?a=b", "https://inner.example.com/1?a=b"},
		{"https://edge.example.com/", "https://inner.example.com", "1?b=c", "https://inner.example.com/1?b=c"},
		{"https://edge.example.com/1?a=b", "https://inner.example.com/1?a=b", "2?c=d", "https://inner.example.com/2?c=d"},
	}
	for _, test := range tests {
		origUrl, _ := url.Parse(test[0])
		orig := &http.Request{
			URL: origUrl,
		}
		requestedUrl, _ := url.Parse(test[1])
		redir, _ := url.Parse(test[2])
		expected := test[3]
		require.Equal(t, expected, RedirectedURL(orig, requestedUrl, redir).String())
	}
}

func TestETagSuffixing(t *testing.T) {
	tok := "-001"
	os.Setenv("ETAG_SUFFIX", tok)
	require.Equal(t, `W/"123-001"`, AddETagSuffix(`W/"123"`))
	require.Equal(t, `"123-001"`, AddETagSuffix(`"123"`))
	require.Equal(t, `123-001`, AddETagSuffix(`123`))
	require.Equal(t, `W/"123-001"`, AddETagSuffix(`W/"123-001"`))
	require.Equal(t, `"123-001"`, AddETagSuffix(`"123-001"`))
	require.Equal(t, `123-001`, AddETagSuffix(`123-001`))

}

func TestETagSuffixStripping(t *testing.T) {
	tok := "-001"
	os.Setenv("ETAG_SUFFIX", tok)
	require.Equal(t, `W/"123"`, StripETagSuffix(`W/"123-001"`))
	require.Equal(t, `W/"123"`, StripETagSuffix(`W/"123"`))
	require.Equal(t, `"123"`, StripETagSuffix(`"123-001"`))
	require.Equal(t, `"123"`, StripETagSuffix(`"123"`))
	require.Equal(t, `123`, StripETagSuffix(`123-001`))
	require.Equal(t, `123`, StripETagSuffix(`123`))
}
