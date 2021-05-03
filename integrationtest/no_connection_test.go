// +build integration

package integrationtest

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/richiefi/rrrouter/config"
	"github.com/richiefi/rrrouter/proxy"
	"github.com/stretchr/testify/require"
)

func TestNoConnection_return_bad_gateway(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
	}
	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: "http://127.0.0.1:13243/$1",
			Internal:    false,
		},
	}, sh.Logger)
	require.Nil(t, err)
	router := proxy.NewRouter(rules, sh.Logger, conf)
	listener := sh.runProxy(router)
	defer listener.Close()

	resp := sh.getURL("/t/asdf", listener.URL)
	defer resp.Body.Close()

	require.Equal(t, resp.StatusCode, 502)
}

func TestNoConnection_retries_with_sleeps(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
		RetryTimes: []int{10, 80, 160, 240},
	}
	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: "http://127.0.0.1:13243/$1",
			Internal:    false,
		},
	}, sh.Logger)
	require.Nil(t, err)
	trp := &TimingRequestPerformer{}
	router := proxy.NewRouterWithPerformer(rules, sh.Logger, conf, trp)
	listener := sh.runProxy(router)
	defer listener.Close()

	resp := sh.getURL("/t/asdf", listener.URL)
	defer resp.Body.Close()

	require.Equal(t, len(trp.callTimes), len(conf.RetryTimes)+1)
	durs := trp.durations()
	t.Log("Call times:", trp.callTimes)
	t.Log("Sleep durations:", durs)
	require.Equal(t, durs[0], time.Millisecond*0)
	for i, rt := range conf.RetryTimes {
		require.True(t, absdur(durs[i+1]-time.Millisecond*time.Duration(rt)) < time.Millisecond*20)
	}
}

func TestNoConnection_rules_with_retry_rule_short_circuit_retries_to_retry_rule_until_exhausted(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
		RetryTimes: []int{10, 80, 160, 240},
	}
	retryRuleSource := proxy.RuleSource{
		Pattern:     "127.0.0.1/t/*",
		Destination: "http://127.0.0.1:13243/retries/go/here",
	}
	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: "http://127.0.0.1:13243/$1",
			RetryRule:   &retryRuleSource,
		},
	}, sh.Logger)
	require.Nil(t, err)
	trp := &TimingRequestPerformer{}
	router := proxy.NewRouterWithPerformer(rules, sh.Logger, conf, trp)
	listener := sh.runProxy(router)
	defer listener.Close()

	resp := sh.getURL("/t/asdf", listener.URL)
	defer resp.Body.Close()

	require.Equal(t, len(conf.RetryTimes)+2, len(trp.callTimes)) // Two initial requests, one original, one retry and retries for the retry rule request
	durs := trp.durations()
	t.Log("Call times:", trp.callTimes)
	t.Log("Sleep durations:", durs)
	require.Equal(t, durs[0], time.Millisecond*0)
	for i, rt := range conf.RetryTimes {
		require.True(t, absdur(durs[i+1]-time.Millisecond*time.Duration(rt)) < time.Millisecond*100)
	}
	for i, req := range trp.callRequests {
		if i == 0 {
			require.Equal(t, "/asdf", req.URL.Path)
		} else {
			require.Equal(t, "/retries/go/here", req.URL.Path)
		}
	}
}

func TestNoConnection_no_POST_retry(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
		RetryTimes: []int{10, 80, 160, 240},
	}
	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: "http://127.0.0.1:13243/$1",
			Internal:    false,
		},
	}, sh.Logger)
	require.Nil(t, err)
	trp := &TimingRequestPerformer{}
	router := proxy.NewRouterWithPerformer(rules, sh.Logger, conf, trp)
	listener := sh.runProxy(router)
	defer listener.Close()

	resp := sh.postForm("/t/asdf", listener.URL, url.Values{})
	defer resp.Body.Close()

	require.Equal(t, len(trp.callTimes), 1)
}

func TestBodyReceivedAfterRetry(t *testing.T) {
	sh := setup(t)
	conf := &config.Config{
		Port:       0,
		MappingURL: "",
		RetryTimes: []int{10, 80, 160, 240},
	}
	port := 13234
	data := `Eros nec lectus est in non, lobortis rutrum eget. Porta sociis posuere accumsan vel sed wisi, suspendisse urna aliquam, arcu id ante felis justo. Risus quasi neque in, et at dui maecenas pulvinar et, mattis sed, quisque blandit mauris sit. Id sollicitudin amet in elit amet. Consectetuer laoreet scelerisque aliquam quam id lobortis, vivamus posuere eget pharetra nascetur ut, scelerisque mattis arcu dui at diam. Amet nulla. Nonummy netus urna aliquam, pellentesque urna sollicitudin aliquam elit interdum, nunc fringilla maecenas ornare phasellus.`

	var badServerReceivedRequest bool
	// 1. Set up a server that reads data from the request but breaks the
	//    connection, triggering retry in the proxy.
	go func() {
		t.Log("Start bad server")
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		require.Nil(t, err)
		defer l.Close()
		conn, err := l.Accept()
		require.Nil(t, err)
		// conn.Close()
		dataToRead := 220
		cdata := make([]byte, dataToRead)
		for dataToRead > 0 {
			n, err := conn.Read(cdata)
			require.Nil(t, err)
			require.True(t, n > 0)
			s := string(cdata[:n])
			t.Log("Read data on bad server:", s)
			dataToRead -= n
		}
		conn.Close()
		l.Close()
		badServerReceivedRequest = true
	}()

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:     "127.0.0.1/t/*",
			Destination: fmt.Sprintf("http://127.0.0.1:%d/$1", port),
			Internal:    false,
		},
	}, sh.Logger)
	require.Nil(t, err)
	attempts := 0
	var targetServer *httptest.Server
	var requestReceived bool
	// 2. Use TimingRequestPerformer's callback to launch the listening server
	//    after a few attempts after initial failures
	trp := &TimingRequestPerformer{
		calledCallback: func() {
			attempts++
			if attempts == 3 {
				l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
				require.Nil(t, err)
				targetServer = &httptest.Server{Listener: l, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Log("Received request on the target server", r)
					bodyData := sh.readRequestBody(r)
					require.Equal(t, bodyData, []byte(data))
					requestReceived = true
				})}}
				targetServer.Start()
			}
		},
	}
	// Wrapper func so defer doesn't capture the initial nil value but instead
	// the value targetServer receives later on
	defer func() {
		targetServer.Close()
	}()

	router := proxy.NewRouterWithPerformer(rules, sh.Logger, conf, trp)
	listener := sh.runProxy(router)
	defer listener.Close()

	bodyBuf := nopCloser{bytes.NewBufferString(data)}

	resp := sh.getURLQueryWithBody("/t/asdf", listener.URL, url.Values{}, nil, bodyBuf)
	defer resp.Body.Close()

	require.Equal(t, len(trp.callTimes), 3)
	require.True(t, requestReceived)
	require.True(t, badServerReceivedRequest)
}

func absdur(d time.Duration) time.Duration {
	if d < 0 {
		return d * -1
	}
	return d
}

type TimingRequestPerformer struct {
	callTimes      []time.Time
	callRequests   []*http.Request
	calledCallback func()
}

func (tr *TimingRequestPerformer) Do(req *http.Request) (*http.Response, error) {
	now := time.Now()
	tr.callTimes = append(tr.callTimes, now)
	tr.callRequests = append(tr.callRequests, req)
	if tr.calledCallback != nil {
		tr.calledCallback()
	}
	return http.DefaultClient.Do(req)
}

func (tr *TimingRequestPerformer) CloseIdleConnections() {
	// CloseIdleConnections implementation here is a NOP method to satisfy an interface. It has no connections to
	// purge or close.
}

func (tr *TimingRequestPerformer) durations() []time.Duration {
	durs := make([]time.Duration, 0, len(tr.callTimes))
	var prevTime time.Time
	for i, t := range tr.callTimes {
		if i == 0 {
			durs = append(durs, 0)
		} else {
			durs = append(durs, t.Sub(prevTime))
		}
		prevTime = t
	}
	return durs
}

type nopCloser struct {
	io.Reader
}

func (nopCloser) Close() error { return nil }
