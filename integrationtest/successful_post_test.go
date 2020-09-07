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

func TestPost_data_gets_to_server(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
	}
	requestReceived := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request on the target server", r)
		require.Equal(t, r.Method, "POST")
		data := sh.readRequestBody(r)
		require.Equal(t, data, []byte("foo=bar"))
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

	resp := sh.postForm("/t/asdf", listener.URL, url.Values{"foo": {"bar"}})
	defer resp.Body.Close()

	require.True(t, requestReceived)
}
