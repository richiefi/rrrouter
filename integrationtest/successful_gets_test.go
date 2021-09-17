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

const (
	brBody    = "\x8B\x02\x80\x5B\x22\x4F\x4B\x22\x5D\x03"
	gzBody    = "\x1F\x8B\x08\x00\x00\x00\x00\x00\x00\xFF\x8A\x56\xF2\xF7\x56\x8A\x05\x04\x00\x00\xFF\xFF\xD0\x64\x5A\x61\x06\x00\x00\x00"
	plainBody = "[\"OK\"]"
)

func TestConnection_client_requests_brotli_but_compression_override_is_not_set_and_client_gets_gzip(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	requestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, "br", r.Header.Get("Accept-Encoding"))
		requestReceived = true
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(gzBody))
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:          "/t/*",
			Destination:   fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:      false,
			Recompression: false,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	header := http.Header{}
	header.Set("Accept-Encoding", "br")
	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, header)
	require.True(t, requestReceived)
	body := sh.readBody(resp)
	require.Equal(t, []byte(gzBody), body)
	require.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
	require.Equal(t, "Authorization", resp.Header.Get("Vary"))
}

func TestConnection_client_requests_brotli_from_origin_gets_brotli(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	requestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, "br", r.Header.Get("Accept-Encoding"))
		requestReceived = true
		w.Header().Set("Content-Encoding", "br")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(brBody))
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:          "/t/*",
			Destination:   fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:      false,
			Recompression: true,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	header := http.Header{}
	header.Set("Accept-Encoding", "br")
	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, header)
	require.True(t, requestReceived)
	body := sh.readBody(resp)
	require.Equal(t, []byte(brBody), body)
	require.Equal(t, resp.Header.Get("Content-Encoding"), "br")
}

func TestConnection_client_requests_brotli_from_gzip_origin_gets_brotli(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	requestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, "br", r.Header.Get("Accept-Encoding"))
		requestReceived = true
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Authorization")
		w.Header().Set("Etag", "1234")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(gzBody))
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:          "/t/*",
			Destination:   fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:      false,
			Recompression: true,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	header := http.Header{}
	header.Set("Accept-Encoding", "br")
	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, header)
	require.True(t, requestReceived)
	body := sh.readBody(resp)
	require.Equal(t, []byte(brBody), body)
	require.Equal(t, "br", resp.Header.Get("Content-Encoding"))
	require.Equal(t, "Authorization, Accept-Encoding", resp.Header.Get("Vary"))
	require.Equal(t, "1234", resp.Header.Get("Etag"))
}

func TestConnection_client_requests_brotli_from_gzip_origin_no_transform_set_gets_gzip(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	requestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, "br", r.Header.Get("Accept-Encoding"))
		requestReceived = true
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Cache-Control", "no-transform")
		w.Header().Set("Vary", "Authorization")
		w.Header().Set("Etag", "1234")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(gzBody))
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:          "/t/*",
			Destination:   fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:      false,
			Recompression: true,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	header := http.Header{}
	header.Set("Accept-Encoding", "br")
	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, header)
	require.True(t, requestReceived)
	body := sh.readBody(resp)
	require.Equal(t, []byte(gzBody), body)
	require.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
	require.Equal(t, "Authorization", resp.Header.Get("Vary"))
	require.Equal(t, "1234", resp.Header.Get("Etag"))
}

func TestConnection_client_requests_gzip_from_gzip_origin_gets_gzip(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	requestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, "gzip, deflate", r.Header.Get("Accept-Encoding"))
		requestReceived = true
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(gzBody))
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:          "/t/*",
			Destination:   fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:      false,
			Recompression: true,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	header := http.Header{}
	header.Set("Accept-Encoding", "gzip, deflate")
	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, header)
	require.True(t, requestReceived)
	body := sh.readBody(resp)
	require.Equal(t, []byte(gzBody), body)
	require.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
	require.Equal(t, "Authorization", resp.Header.Get("Vary"))
}

func TestConnection_client_requests_brotli_from_plaintext_whitelisted_content_type_origin_gets_brotli(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	requestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, "br", r.Header.Get("Accept-Encoding"))
		requestReceived = true
		if r.URL.Path == "/text" {
			w.Header().Set("Content-Type", "text/whatever")
		} else if r.URL.Path == "/json" {
			w.Header().Set("Content-Type", "application/json")
		} else if r.URL.Path == "/xml" {
			w.Header().Set("Content-Type", "application/xml")
		}
		if len(r.URL.Query().Get("encoding")) > 0 {
			w.Header().Set("Content-Encoding", r.URL.Query().Get("encoding"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(plainBody))
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:          "/t/*",
			Destination:   fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:      false,
			Recompression: true,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	// JSON, plain
	header := http.Header{}
	header.Set("Accept-Encoding", "br")
	resp := sh.getURLQuery("/t/json?encoding=identity", listener.URL, url.Values{}, header)
	require.True(t, requestReceived)
	body := sh.readBody(resp)
	require.Equal(t, []byte(brBody), body)
	require.Equal(t, "br", resp.Header.Get("Content-Encoding"))
	require.Equal(t, "Accept-Encoding", resp.Header.Get("Vary"))

	// JSON, plain, no content-encoding header in the source
	header = http.Header{}
	header.Set("Accept-Encoding", "br")
	resp = sh.getURLQuery("/t/json", listener.URL, url.Values{}, header)
	require.True(t, requestReceived)
	body = sh.readBody(resp)
	require.Equal(t, []byte(brBody), body)
	require.Equal(t, "br", resp.Header.Get("Content-Encoding"))
	require.Equal(t, "Accept-Encoding", resp.Header.Get("Vary"))

	// text/*, plain
	header = http.Header{}
	header.Set("Accept-Encoding", "br")
	resp = sh.getURLQuery("/t/text?encoding=identity", listener.URL, url.Values{}, header)
	require.True(t, requestReceived)
	body = sh.readBody(resp)
	require.Equal(t, []byte(brBody), body)
	require.Equal(t, "br", resp.Header.Get("Content-Encoding"))
	require.Equal(t, "Accept-Encoding", resp.Header.Get("Vary"))

	// application/xml, plain: not compressed
	header = http.Header{}
	header.Set("Accept-Encoding", "br")
	resp = sh.getURLQuery("/t/xml?encoding=identity", listener.URL, url.Values{}, header)
	require.True(t, requestReceived)
	body = sh.readBody(resp)
	require.Equal(t, []byte(plainBody), body)
	require.Equal(t, "identity", resp.Header.Get("Content-Encoding"))
	require.Equal(t, "", resp.Header.Get("Vary"))
}

func TestConnection_broken_client_requests_gzip_identity_from_plaintext_whitelisted_content_type_origin_gets_plaintext(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
	requestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, "gzip; identity", r.Header.Get("Accept-Encoding"))
		requestReceived = true
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(gzBody))
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:          "/t/*",
			Destination:   fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:      false,
			Recompression: true,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	// JSON, plain
	header := http.Header{}
	header.Set("Accept-Encoding", "gzip; identity")
	resp := sh.getURLQuery("/t/json", listener.URL, url.Values{}, header)
	require.True(t, requestReceived)
	body := sh.readBody(resp)
	require.Equal(t, []byte(plainBody), body)
	require.Equal(t, "", resp.Header.Get("Content-Encoding"))
	require.Equal(t, "", resp.Header.Get("Vary"))
}

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
			Path:        "/t/*",
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
			Path:        "/t/*",
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
			Path:        "/t/*",
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
			Path:        "/t/*",
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
			Path:        "/t/*",
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
			Path:        "/t/*",
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
			Path:        "/t/*",
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
			Path:        "/t/*",
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
			Path:        "/t/*",
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

func TestConnection_host_header_behaviors(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
	}

	// HostHeaderDefault

	receivedRequest := false
	originHostHeader := ""
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		receivedRequest = true
		originHostHeader = r.Host
		w.WriteHeader(http.StatusOK)
	}))

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:        "/t/*",
			Destination: fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:    false,
			HostHeader:  "",
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	sh.getURL("/t/asdf", listener.URL)
	require.True(t, receivedRequest)
	sUrl, _ := url.Parse(targetServer.URL)
	require.Equal(t, sUrl.Host, originHostHeader)
	targetServer.Close()

	// HostHeaderOriginal

	receivedRequest = false
	originHostHeader = ""
	targetServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		receivedRequest = true
		originHostHeader = r.Host
		w.WriteHeader(http.StatusOK)
	}))

	rules, err = proxy.NewRules([]proxy.RuleSource{
		{
			Host:        "example.com",
			Path:        "/t/*",
			Destination: fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:    false,
			HostHeader:  "original",
		},
	}, sh.Logger)
	require.Nil(t, err)
	router = proxy.NewRouter(rules, sh.Logger, conf)
	listener = sh.runProxy(router)
	defer listener.Close()

	hdrs := http.Header{}
	hdrs.Set("Host", "example.com")
	sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, hdrs)
	require.True(t, receivedRequest)
	require.Equal(t, "example.com", originHostHeader)
	targetServer.Close()

	// HostHeaderDestination

	receivedRequest = false
	originHostHeader = ""
	targetServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		receivedRequest = true
		originHostHeader = r.Host
		w.WriteHeader(http.StatusOK)
	}))

	rules, err = proxy.NewRules([]proxy.RuleSource{
		{
			Host:        "example.com",
			Path:        "/t/*",
			Destination: fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:    false,
			HostHeader:  "destination",
		},
	}, sh.Logger)
	require.Nil(t, err)
	router = proxy.NewRouter(rules, sh.Logger, conf)
	listener = sh.runProxy(router)
	defer listener.Close()

	hdrs = http.Header{}
	hdrs.Set("Host", "example.com")
	sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, hdrs)
	require.True(t, receivedRequest)
	sUrl, _ = url.Parse(targetServer.URL)
	require.Equal(t, sUrl.Host, originHostHeader)
	targetServer.Close()

	// HostHeaderOverride

	receivedRequest = false
	originHostHeader = ""
	targetServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		receivedRequest = true
		originHostHeader = r.Host
		w.WriteHeader(http.StatusOK)
	}))

	rules, err = proxy.NewRules([]proxy.RuleSource{
		{
			Host:        "example.com",
			Path:        "/t/*",
			Destination: fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:    false,
			HostHeader:  "example.com:3800",
		},
	}, sh.Logger)
	require.Nil(t, err)
	router = proxy.NewRouter(rules, sh.Logger, conf)
	listener = sh.runProxy(router)
	defer listener.Close()

	hdrs = http.Header{}
	hdrs.Set("Host", "example.com:3800")
	sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, hdrs)
	require.True(t, receivedRequest)
	require.Equal(t, "example.com:3800", originHostHeader)
	targetServer.Close()
}

func TestConnection_access_control_allow_origin_override_passed_to_response(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
	}

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:            "/t/*",
			Destination:     fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:        false,
			ResponseHeaders: map[string]string{"access-control-allow-origin": "a,b"},
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	resp := sh.getURL("/t/asdf", listener.URL)
	require.Equal(t, "a,b", resp.Header.Get("access-control-allow-origin"))
}

func TestConnection_timing_allow_origin_override_passed_to_response(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
	}

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:            "/t/*",
			Destination:     fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:        false,
			ResponseHeaders: map[string]string{"timing-allow-origin ": " a,b"},
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	resp := sh.getURL("/t/asdf", listener.URL)
	require.Equal(t, "a,b", resp.Header.Get("timing-allow-origin"))
}

func TestConnection_redirects_pass_rrrouter_by_default(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
	}

	for _, status := range []int{301, 302, 303, 307, 308} {
		targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Log("Received request on the target server", r)
			w.WriteHeader(status)
		}))
		defer targetServer.Close()

		rules, err := proxy.NewRules([]proxy.RuleSource{
			{
				Path:        "/t/*",
				Destination: fmt.Sprintf("%s/$1", targetServer.URL),
				Internal:    false,
			},
		}, sh.Logger)
		require.Nil(t, err)
		router := proxy.NewRouter(rules, sh.Logger, conf)
		listener := sh.runProxy(router)
		defer listener.Close()

		resp := sh.getURL("/t/asdf", listener.URL)
		require.Equal(t, status, resp.StatusCode)
	}
}

func TestConnection_flatten_redirects_follows_all_redirections(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
	}

	type statusLocation struct {
		status   int
		location string
	}
	sls := []statusLocation{{status: 302, location: "/matches/1st"}, {status: 307, location: "/2nd/does-not-match"}, {status: 200}}
	var sl statusLocation
	timesOriginHit := 0
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		sl, sls = sls[0], sls[1:]
		if sl.status != 200 {
			w.Header().Set("location", sl.location)
			w.WriteHeader(sl.status)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("ab"))
	}))
	defer targetServer.Close()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:             "/t/matches/*",
			Destination:      fmt.Sprintf("%s/$1", targetServer.URL),
			Internal:         false,
			FlattenRedirects: true,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	resp := sh.getURLQuery("/t/matches/asdf", listener.URL, url.Values{}, http.Header{"accept-encoding": []string{"gzip"}})
	require.Equal(t, resp.StatusCode, 200)
	require.Equal(t, timesOriginHit, 3)
}
