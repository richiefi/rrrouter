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

func TestCopyTraffic_internal_headers_added(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	targetRequestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, r.Header.Get("Richie-Routing-Secret"), "a")
		origip := r.Header.Get("Richie-Originating-IP")
		require.True(t, origip == "127.0.0.1" || origip == "::1", origip)
		require.Equal(t, len(r.Header.Get("Richie-Request-ID")), 36)
		targetRequestReceived = true
	}))
	defer targetServer.Close()

	copyRequestReceived := false
	copyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the copy server", r)
		require.Equal(t, r.Header.Get("Richie-Routing-Secret"), "a")
		origip := r.Header.Get("Richie-Originating-IP")
		require.True(t, origip == "127.0.0.1" || origip == "::1", origip)
		require.Equal(t, len(r.Header.Get("Richie-Request-ID")), 36)
		copyRequestReceived = true
	}))
	defer copyServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: fmt.Sprintf("%s/$1", copyServer.URL),
			Internal:    true,
			Type:        sp("copy_traffic"),
		},
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:    true,
		},
	}, sh.Logger)
	require.Nil(t, err)
	t.Log(rules)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	resp := sh.getURL("/t/asdf", listener.URL)
	defer resp.Body.Close()

	require.True(t, targetRequestReceived)
	require.True(t, copyRequestReceived)
}

func TestCopyTraffic_no_internal_headers_to_external_copy(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	targetRequestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, r.Header.Get("Richie-Routing-Secret"), "a")
		origip := r.Header.Get("Richie-Originating-IP")
		require.True(t, origip == "127.0.0.1" || origip == "::1", origip)
		require.Equal(t, len(r.Header.Get("Richie-Request-ID")), 36)
		targetRequestReceived = true
	}))
	defer targetServer.Close()

	copyRequestReceived := false
	copyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the copy server", r)
		require.Equal(t, r.Header.Get("Richie-Routing-Secret"), "")
		require.Equal(t, r.Header.Get("Richie-Originating-IP"), "")
		require.Equal(t, r.Header.Get("Richie-Request-ID"), "")
		copyRequestReceived = true
	}))
	defer copyServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: fmt.Sprintf("%s/$1", copyServer.URL),
			Internal:    false,
			Type:        sp("copy_traffic"),
		},
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

	require.True(t, targetRequestReceived)
	require.True(t, copyRequestReceived)
}

func TestCopyTraffic_copy_works_without_matching_proxy_target(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	targetRequestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Received request on the target server", r)
		targetRequestReceived = true
	}))
	defer targetServer.Close()

	copyRequestReceived := false
	copyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the copy server", r)
		require.Equal(t, r.Header.Get("Richie-Routing-Secret"), "")
		require.Equal(t, r.Header.Get("Richie-Originating-IP"), "")
		require.Equal(t, r.Header.Get("Richie-Request-ID"), "")
		copyRequestReceived = true
	}))
	defer copyServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: fmt.Sprintf("%s/$1", copyServer.URL),
			Internal:    false,
			Type:        sp("copy_traffic"),
		},
		{
			Pattern:     "127.0.0.1/nomatch/*",
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

	require.False(t, targetRequestReceived)
	require.True(t, copyRequestReceived)
}

func TestCopyTraffic_copy_error_doesnt_go_to_caller(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	targetRequestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, r.Header.Get("Richie-Routing-Secret"), "a")
		origip := r.Header.Get("Richie-Originating-IP")
		require.True(t, origip == "127.0.0.1" || origip == "::1", origip)
		require.Equal(t, len(r.Header.Get("Richie-Request-ID")), 36)
		targetRequestReceived = true
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: fmt.Sprintf("http://localhost:%d/$1", 18237),
			Internal:    false,
			Type:        sp("copy_traffic"),
		},
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

	require.True(t, targetRequestReceived)
}

func TestCopyTraffic_copy_both_receive_request_body(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	targetRequestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, r.Header.Get("Richie-Routing-Secret"), "a")
		origip := r.Header.Get("Richie-Originating-IP")
		require.True(t, origip == "127.0.0.1" || origip == "::1", origip)
		require.Equal(t, len(r.Header.Get("Richie-Request-ID")), 36)
		data := sh.readRequestBody(r)
		require.Equal(t, data, []byte("foo=bar"))
		targetRequestReceived = true
	}))
	defer targetServer.Close()

	copyRequestReceived := false
	copyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the copy server", r)
		require.Equal(t, r.Header.Get("Richie-Routing-Secret"), "a")
		origip := r.Header.Get("Richie-Originating-IP")
		require.True(t, origip == "127.0.0.1" || origip == "::1", origip)
		require.Equal(t, len(r.Header.Get("Richie-Request-ID")), 36)
		data := sh.readRequestBody(r)
		require.Equal(t, data, []byte("foo=bar"))
		copyRequestReceived = true
	}))
	defer copyServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: fmt.Sprintf("%s/$1", copyServer.URL),
			Internal:    true,
			Type:        sp("copy_traffic"),
		},
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

	resp := sh.postForm("/t/asdf", listener.URL, url.Values{"foo": {"bar"}})
	defer resp.Body.Close()

	require.True(t, targetRequestReceived)
	require.True(t, copyRequestReceived)
}

func TestCopyTraffic_exampleapp_rule_matches_only_exampleapp(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
	}
	targetRequestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		targetRequestReceived = true
	}))
	defer targetServer.Close()

	copyRequestReceived := false
	copyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the copy server", r)
		copyRequestReceived = true
	}))
	defer copyServer.Close()

	rulestr := fmt.Sprintf(`{"rules": [
        {
            "destination": "%[1]s/$1/exampleapp/$2.exampleapp.js",
            "internal": false,
            "pattern": "http://127.0.0.1/*/exampleapp/*.exampleapp.js",
            "type": "copy_traffic"
        },
        {
            "destination": "%[2]s/android/$1",
            "internal": false,
            "pattern": "http://127.0.0.1/android/*"
        },
        {
            "destination": "%[2]s/ios/$1",
            "internal": false,
            "pattern": "http://127.0.0.1/ios/*"
        },
        {
            "destination": "%[2]s/windows/$1",
            "internal": false,
            "pattern": "http://127.0.0.1/windows/*"
        }
    ]}`, copyServer.URL, targetServer.URL)

	t.Log("rulestr:", rulestr)

	rules, err := proxy.ParseRules([]byte(rulestr), sh.Logger)

	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)

	defer listener.Close()

	resp := sh.getURL("/android/exampleapp/10.exampleapp.js", listener.URL)
	defer resp.Body.Close()

	require.True(t, targetRequestReceived)
	require.True(t, copyRequestReceived)

	targetRequestReceived = false
	copyRequestReceived = false

	resp = sh.getURL("/ios/test.app.1/slots.json", listener.URL)
	defer resp.Body.Close()

	require.True(t, targetRequestReceived)
	require.False(t, copyRequestReceived)
}

func TestCopyTraffic_matches_with_parameters(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	targetRequestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, r.Header.Get("Richie-Routing-Secret"), "a")
		origip := r.Header.Get("Richie-Originating-IP")
		require.True(t, origip == "127.0.0.1" || origip == "::1", origip)
		require.Equal(t, len(r.Header.Get("Richie-Request-ID")), 36)
		require.Equal(t, r.URL.Query(), url.Values{"junk": {"05fbe0b4-a4a3-41e8-9f84-1831b9995fe8"}})
		targetRequestReceived = true
	}))
	defer targetServer.Close()

	copyRequestReceived := false
	copyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the copy server", r)
		require.Equal(t, r.Header.Get("Richie-Routing-Secret"), "a")
		origip := r.Header.Get("Richie-Originating-IP")
		require.True(t, origip == "127.0.0.1" || origip == "::1", origip)
		require.Equal(t, len(r.Header.Get("Richie-Request-ID")), 36)
		require.Equal(t, r.URL.Query(), url.Values{"junk": {"05fbe0b4-a4a3-41e8-9f84-1831b9995fe8"}})
		copyRequestReceived = true
	}))
	defer copyServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "http://127.0.0.1/*/*/slots.json",
			Destination: fmt.Sprintf("%s/v1/slots/$1/$2/slots.json", copyServer.URL),
			Internal:    true,
			Type:        sp("copy_traffic"),
		},
		{
			Pattern:     "http://127.0.0.1/windows/*",
			Destination: fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:    true,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	resp := sh.getURLQuery("/windows/test.app.2/slots.json", listener.URL, url.Values{"junk": {"05fbe0b4-a4a3-41e8-9f84-1831b9995fe8"}}, nil)
	defer resp.Body.Close()

	require.True(t, targetRequestReceived)
	require.True(t, copyRequestReceived)
}

func sp(s string) *string {
	return &s
}
