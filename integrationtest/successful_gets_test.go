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

func TestConnection_internal_headers_added(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	requestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, r.Header.Get("Richie-Routing-Secret"), "a")
		origip := r.Header.Get("Richie-Originating-IP")
		require.True(t, origip == "127.0.0.1" || origip == "::1", origip)
		require.Equal(t, len(r.Header.Get("Richie-Request-ID")), 36)
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
}

func TestConnection_internal_headers_passed_through(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	requestReceived := false
	reqID := "6ba9b810-9ddd-12d1-45b4-00c04fd430c8"
	origIP := "42.12.11.160"
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, r.Header.Get("Richie-Routing-Secret"), "a")
		require.Equal(t, r.Header.Get("Richie-Originating-IP"), origIP)
		require.Equal(t, r.Header.Get("Richie-Request-ID"), reqID)
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
	header.Set("Richie-Routing-Secret", "a")
	header.Set("Richie-Originating-IP", origIP)
	header.Set("Richie-Request-ID", reqID)
	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, header)
	defer resp.Body.Close()

	require.True(t, requestReceived)
}

func TestConnection_external_no_headers_added(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	requestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, r.Header.Get("Richie-Routing-Secret"), "")
		require.Equal(t, r.Header.Get("Richie-Originating-IP"), "")
		require.Equal(t, len(r.Header.Get("Richie-Request-ID")), 0)
		requestReceived = true
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:    false,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	resp := sh.getURL("/t/asdf", listener.URL)
	defer resp.Body.Close()

	require.True(t, requestReceived)
}

func TestConnection_internal_headers_stripped_with_external_target(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	requestReceived := false
	reqID := "6ba9b810-9ddd-12d1-45b4-00c04fd430c8"
	origIP := "42.12.11.160"
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, r.Header.Get("Richie-Routing-Secret"), "")
		require.Equal(t, r.Header.Get("Richie-Originating-IP"), "")
		require.Equal(t, len(r.Header.Get("Richie-Request-ID")), 0)
		requestReceived = true
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:    false,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	header := http.Header{}
	header.Set("Richie-Routing-Secret", "a")
	header.Set("Richie-Originating-IP", origIP)
	header.Set("Richie-Request-ID", reqID)
	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, header)
	defer resp.Body.Close()
	require.True(t, requestReceived)
}

func TestConnection_other_headers_passed_through_to_internal(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	requestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, r.Header.Get("Custom-Header-With-No-Special-Meaning"), "flap flap flap")
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
	header.Set("Custom-Header-With-No-Special-Meaning", "flap flap flap")
	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, header)
	defer resp.Body.Close()
	require.True(t, requestReceived)
}

func TestConnection_other_headers_passed_through_to_external(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	requestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, r.Header.Get("Custom-Header-With-No-Special-Meaning"), "pew pew pew")
		requestReceived = true
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:    false,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	header := http.Header{}
	header.Set("Custom-Header-With-No-Special-Meaning", "pew pew pew")
	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, header)
	defer resp.Body.Close()
	require.True(t, requestReceived)
}

func TestConnection_response_headers_and_successful_status_passed_through_to_client(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
	}
	requestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		requestReceived = true
		header := w.Header()
		header.Set("Custom-Header-In-Response", "Fancy Values Here")
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:    false,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	resp := sh.getURL("/t/asdf", listener.URL)
	defer resp.Body.Close()
	require.Equal(t, resp.StatusCode, http.StatusOK)
	require.Equal(t, resp.Header.Get("Custom-Header-In-Response"), "Fancy Values Here")
	require.True(t, requestReceived)
}

func TestConnection_response_non_success_status_code_passed_through_to_the_client(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
	}
	requestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		requestReceived = true
		w.WriteHeader(http.StatusNotFound)
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:    false,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	resp := sh.getURL("/t/asdf", listener.URL)
	defer resp.Body.Close()
	require.Equal(t, resp.StatusCode, http.StatusNotFound)
	require.True(t, requestReceived)
}

func TestConnection_response_body_passed_through_to_the_client(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
	}
	requestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		requestReceived = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello"))
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:    false,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	resp := sh.getURL("/t/asdf", listener.URL)
	require.Equal(t, resp.StatusCode, http.StatusOK)
	require.True(t, requestReceived)
	body := sh.readBody(resp)
	require.Equal(t, body, []byte("Hello"))
}
