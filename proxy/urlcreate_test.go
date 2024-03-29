package proxy

import (
	"net/url"
	"testing"

	"github.com/richiefi/rrrouter/testhelp"
	"github.com/stretchr/testify/require"
)

func TestTargetURL(t *testing.T) {
	tests := []struct {
		source *url.URL
		expect *url.URL
	}{
		{
			source: uparse("http://source.com/s/1"),
			expect: uparse("https://target.com/1"),
		},
		{
			source: uparse("http://source.com/s/1?k=v"),
			expect: uparse("https://target.com/1?k=v"),
		},
		{
			source: uparse("http://source.com/s/1?k=v#Frag"),
			expect: uparse("https://target.com/1?k=v#Frag"),
		},
		{
			source: uparse("https://source.com/s/1?k=v#Frag"),
			expect: uparse("https://target.com/1?k=v#Frag"),
		},
	}
	logger := testhelp.NewLogger(t)
	rules := &Rules{
		rules: []*Rule{
			createRule("", "source.com", "/s/*", "https://target.com/$1"),
		},
		logger: logger,
	}
	router := &router{
		rules:  rules,
		logger: logger,
	}
	for _, test := range tests {
		res, err := router.createOutgoingURLs(test.source, "GET", nil)
		require.Nil(t, err)
		require.Equal(t, test.expect, res.url)
	}
}

func uparse(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func createRule(s, h, path, dest string) *Rule {
	r, err := NewRule(true, s, h, path, dest, false, map[string]bool{}, ruleTypeProxy, HostHeader{Behavior: HostHeaderDefault}, false, "", 0, nil, map[string]string{}, false, nil)
	if err != nil {
		panic(err)
	}
	return r
}
