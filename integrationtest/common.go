// +build integration

package integrationtest

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"github.com/richiefi/rrrouter/config"
	"github.com/richiefi/rrrouter/proxy"
	"github.com/richiefi/rrrouter/server"
	"github.com/richiefi/rrrouter/testhelp"
	"github.com/stretchr/testify/require"

	apexlog "github.com/apex/log"
)

func setup(t *testing.T) *ServerHelper {
	logger := newLogger(t)
	serverHelper := &ServerHelper{Test: t, Logger: logger}
	return serverHelper
}

func newLogger(t *testing.T) *apexlog.Logger {
	logger := &apexlog.Logger{
		Handler: testhelp.NewApexLogBridge(t),
		Level:   apexlog.DebugLevel,
	}
	return logger
}

type testLogWriter struct {
	t *testing.T
}

func (tlw *testLogWriter) Write(p []byte) (n int, err error) {
	tlw.t.Log(string(p))
	return len(p), nil
}

type ServerHelper struct {
	Test   *testing.T
	Logger *apexlog.Logger
}

func newTestLogWriter(t *testing.T) io.Writer {
	tlw := testLogWriter{t: t}
	return &tlw
}

func (sh *ServerHelper) runProxy(router proxy.Router) *httptest.Server {
	smux := http.NewServeMux()
	conf := &config.Config{}
	server.ConfigureServeMux(smux, conf, router, sh.Logger, nil)
	return httptest.NewServer(smux)
}

func (sh *ServerHelper) readRequestBody(req *http.Request) []byte {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		sh.Test.Fatal("Error reading request body:", err)
	}
	return body
}

func (sh *ServerHelper) readBody(resp *http.Response) []byte {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		sh.Test.Fatal("Error reading response body:", err)
	}
	return body
}

func (sh *ServerHelper) postForm(path string, testServerURL string, form url.Values) *http.Response {
	url := testServerURL + path
	req, err := http.NewRequest("POST", url, strings.NewReader(form.Encode()))
	if err != nil {
		sh.Test.Fatal("Error creating request:", err)
	}
	req.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	reqdump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		sh.Test.Fatalf("Error dumping request: %s", err.Error())
	}
	sh.Test.Log("Sending request:", string(reqdump))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		sh.Test.Fatalf("Error POSTing to %s: %s", path, err.Error())
	}
	return resp
}

func (sh *ServerHelper) expectStatus(resp *http.Response, expect int, msg string) {
	require.Equal(sh.Test, resp.StatusCode, expect, msg)
}

func (sh *ServerHelper) getURLQuery(path string, testServerURL string, query url.Values, header http.Header) *http.Response {
	return sh.URLQueryWithBody("GET", path, testServerURL, query, header, nil)
}

func (sh *ServerHelper) headURLQuery(path string, testServerURL string, query url.Values, header http.Header) *http.Response {
	return sh.URLQueryWithBody("HEAD", path, testServerURL, query, header, nil)
}

func (sh *ServerHelper) getURLQueryWithBody(path string, testServerURL string, query url.Values, header http.Header, body io.ReadCloser) *http.Response {
	return sh.URLQueryWithBody("GET", path, testServerURL, query, header, body)
}

func (sh *ServerHelper) URLQueryWithBody(method string, path string, testServerURL string, query url.Values, header http.Header, body io.ReadCloser) *http.Response {
	urlstr := testServerURL + path
	if len(query) > 0 {
		urlstr += "?" + query.Encode()
	}
	req, err := http.NewRequest(method, urlstr, nil)
	if body != nil {
		req.Body = body
	}
	if err != nil {
		sh.Test.Fatal("Error creating request:", err)
	}
	for hn, hvs := range header {
		for _, hv := range hvs {
			req.Header.Add(hn, hv)
		}
	}
	host := header.Get("Host")
	if len(host) > 0 {
		req.Host = host
	}
	reqdump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		sh.Test.Fatal("Error dumping request:", err)
	}
	sh.Test.Log("Sending request:", string(reqdump))
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		sh.Test.Fatalf("Error GETting %s: %s", path, err.Error())
	}
	return resp
}

func (sh *ServerHelper) getURL(path string, testServerURL string) *http.Response {
	return sh.getURLQuery(path, testServerURL, url.Values{}, http.Header{})
}
