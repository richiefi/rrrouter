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

func TestSecret_unknown_denied(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	requestReceived := false
	reqID := "6ba9b810-9ddd-12d1-45b4-00c04fd430c8"
	origIP := "192.0.2.150"
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		requestReceived = true
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:    true,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	header := http.Header{}
	header.Set("Richie-Routing-Secret", "b")
	header.Set("Richie-Originating-IP", origIP)
	header.Set("Richie-Request-ID", reqID)
	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, header)
	defer resp.Body.Close()

	require.False(t, requestReceived)
	require.Equal(t, resp.StatusCode, 407)
}

func TestSecret_old_accepted(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a", "b", "c", "d"},
	}
	requestReceived := false
	reqID := "6ba9b810-9ddd-12d1-45b4-00c04fd430c8"
	origIP := "192.0.2.150"
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		requestReceived = true
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:    true,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	header := http.Header{}
	header.Set("Richie-Routing-Secret", "c")
	header.Set("Richie-Originating-IP", origIP)
	header.Set("Richie-Request-ID", reqID)
	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, header)
	defer resp.Body.Close()

	require.True(t, requestReceived)
	require.Equal(t, resp.StatusCode, 200)
}

func TestSecret_first_sent(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a", "b", "c", "d"},
	}
	requestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, r.Header.Get("Richie-Routing-Secret"), "a")
		requestReceived = true
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:    true,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	resp := sh.getURL("/t/asdf", listener.URL)
	defer resp.Body.Close()

	require.True(t, requestReceived)
	require.Equal(t, resp.StatusCode, 200)
}
