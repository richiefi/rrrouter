// +build integration

package integrationtest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/richiefi/rrrouter/config"
	"github.com/richiefi/rrrouter/proxy"
	"github.com/richiefi/rrrouter/server"
	"github.com/stretchr/testify/require"
)

func TestSystemInfo_requires_auth(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
		AdminName:  "admin",
		AdminPass:  "pass",
	}
	rules, err := proxy.NewRules([]proxy.RuleSource{}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)

	smux := http.NewServeMux()
	server.ConfigureServeMux(smux, conf, router, sh.Logger)

	listener := httptest.NewServer(smux)
	defer listener.Close()

	resp := sh.getURL("/__SYSTEMINFO", listener.URL)
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestSystemInfo_disabled_without_auth(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
	}
	rules, err := proxy.NewRules([]proxy.RuleSource{}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)

	smux := http.NewServeMux()
	server.ConfigureServeMux(smux, conf, router, sh.Logger)

	listener := httptest.NewServer(smux)
	defer listener.Close()

	resp := sh.getURL("/__SYSTEMINFO", listener.URL)
	defer resp.Body.Close()

	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
