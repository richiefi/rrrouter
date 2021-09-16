// +build integration

package integrationtest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/richiefi/rrrouter/config"
	"github.com/richiefi/rrrouter/proxy"
	"github.com/stretchr/testify/require"
)

func TestConnection_hop_by_hop_headers_filtered(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
	}
	requestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, r.Header.Get("Proxy-Authenticate"), "")
		require.Equal(t, r.Header.Get("Custom-Header"), "should_not_be_filtered")
		requestReceived = true
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "/t/*",
			Destination: fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:    true,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	header := http.Header{}
	// Proxy-Authenticate is one of the hop by hop headers defined in HTTP 1.1
	// that should be filtered out by proxies.
	header.Set("Proxy-Authenticate", "should_be_filtered")
	header.Set("Custom-Header", "should_not_be_filtered")
	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, header)
	defer resp.Body.Close()

	require.True(t, requestReceived)
}
