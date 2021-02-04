package proxy

import (
	"bytes"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	apexlog "github.com/apex/log"
	uuid "github.com/satori/go.uuid"

	"github.com/richiefi/rrrouter/config"
	"github.com/richiefi/rrrouter/usererror"
	"github.com/richiefi/rrrouter/util"
)

const (
	headerRichieRoutingSecret = "Richie-Routing-Secret"
	headerRichieOriginatingIP = "Richie-Originating-IP"
	headerRichieRequestID     = "Richie-Request-ID"
)

type requestResult struct {
	Response      *http.Response
	Recompression util.Recompression
}

// Router is the meat of rrrouter
type Router interface {
	RouteRequest(*http.Request) (*requestResult, error)
}

type requestPerformer interface {
	Do(req *http.Request) (resp *http.Response, err error)
	CloseIdleConnections()
}

type roundTripPerformer struct {
	roundTripper purgeableRoundTripper
}

type purgeableRoundTripper interface {
	// purgeableRoundTripper is a round tripper whose inactive connections can be purged (closed, as stated in the
	// net pkg documentation).
	// Satisfied by *http.Transport, for instance.

	http.RoundTripper
	CloseIdleConnections()
}

func (rp *roundTripPerformer) Do(req *http.Request) (*http.Response, error) {
	return rp.roundTripper.RoundTrip(req)
}

func (rp *roundTripPerformer) CloseIdleConnections() {
	rp.roundTripper.CloseIdleConnections()
}

type router struct {
	rules            *Rules
	logger           *apexlog.Logger
	config           *config.Config
	requestPerformer requestPerformer
}

// NewRouter creates a new router with given Rules
func NewRouter(rules *Rules, logger *apexlog.Logger, conf *config.Config) Router {
	// Same values as in DefaultTransport, with the addition of
	// increased MaxIdleConnsPerHost (it defaults to DefaultMaxIdleConnsPerHost)
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   10,
	}

	return &router{
		rules:            rules,
		logger:           logger,
		config:           conf,
		requestPerformer: &roundTripPerformer{roundTripper: transport},
	}
}

// NewRouterWithPerformer is NewRouter with a specific requestPerformer
func NewRouterWithPerformer(rules *Rules, logger *apexlog.Logger, conf *config.Config, performer requestPerformer) Router {
	return &router{
		rules:            rules,
		logger:           logger,
		config:           conf,
		requestPerformer: performer,
	}
}

func (r *router) RouteRequest(req *http.Request) (*requestResult, error) {
	logctx := r.logger.WithFields(apexlog.Fields{"func": "router.RouteRequest"})
	logctx.Debug("Enter")
	requestsResult, err := r.createOutgoingRequests(req)
	if err != nil {
		logctx.WithError(err).Error("error creating outgoing request")
		return nil, err
	}

	twoTargets := requestsResult.copyRequest != nil && requestsResult.mainRequest != nil
	canRetry := retryable(req)

	var bodyData []byte
	if twoTargets || canRetry {
		logctx.WithFields(apexlog.Fields{"twoTargets": twoTargets, "canRetry": canRetry}).Debug("Both copy and proxy targets found or request was retryable, reading request body to memory")
		var err error
		bodyData, err = ioutil.ReadAll(req.Body)
		if err != nil {
			logctx.WithError(err).Warn("Error reading request body")
			return nil, usererror.CreateError(http.StatusBadRequest, "Couldn't read request body")
		}
		if requestsResult.copyRequest != nil {
			requestsResult.copyRequest.Body = newByteSliceBody(bodyData)
		}
		if requestsResult.mainRequest != nil {
			requestsResult.mainRequest.Body = newByteSliceBody(bodyData)
		}
	}
	if requestsResult.copyRequest != nil {
		copyResp, err := r.performRequest(requestsResult.copyRequest, bodyData)
		if err != nil {
			logctx.WithError(err).Error("Error performing copy request")
		} else {
			logctx.WithFields(apexlog.Fields{"copyRequest.URL": requestsResult.copyRequest.URL, "copyResponse.Status": copyResp.Status}).Info("Copy request performed")
			defer copyResp.Body.Close()
		}
	}

	var mainResp *http.Response
	if requestsResult.mainRequest != nil {
		mainResp, err = r.performRequest(requestsResult.mainRequest, bodyData)
		if err != nil {
			logctx.WithError(err).Error("Error performing main request")
			return nil, err
		}
		logctx.Debug("Successfully performed request")
	} else {
		return nil, usererror.BuildError(usererror.Fields{"URL": req.URL.String()}).CreateError(http.StatusNotFound, "No destination found for request target")
	}

	recompression := util.Recompression{Add: util.CompressionTypeNone, Remove: util.CompressionTypeNone}
	if requestsResult.recompression {
		recompression = util.GetRecompression(req.Header.Get("Accept-Encoding"), mainResp.Header.Get("Content-Encoding"), mainResp.Header.Get("Content-Type"))
	}

	return &requestResult{
		Response:      mainResp,
		Recompression: recompression,
	}, nil
}

type dummyReadCloser struct {
	io.Reader
}

func (d *dummyReadCloser) Close() error {
	return nil
}

func newByteSliceBody(b []byte) *dummyReadCloser {
	return &dummyReadCloser{Reader: bytes.NewReader(b)}
}

func setContentLength(req *http.Request) error {
	requestData, err := ioutil.ReadAll(req.Body)

	if err == io.EOF {
		req.Body = newByteSliceBody([]byte{})
		req.ContentLength = 0
		return nil
	} else if err != nil {
		return err
	}

	req.Body = newByteSliceBody(requestData)
	req.ContentLength = int64(len(requestData))
	return nil
}

func (r *router) performRequest(req *http.Request, requestData []byte) (*http.Response, error) {
	logctx := r.logger.WithFields(apexlog.Fields{"func": "router.performRequest"})
	logctx.Debug("Enter")

	var err error
	var resp *http.Response

	if retryable(req) {
		sleepTimes := make([]time.Duration, len(r.config.RetryTimes)+1)
		for i, rt := range r.config.RetryTimes {
			sleepTimes[i+1] = time.Millisecond * time.Duration(rt)
		}
		for _, sleepTime := range sleepTimes {
			if err != nil {
				logctx.WithError(err).WithField("sleepTime", sleepTime).Warn("Error performing new request, will sleep")
				time.Sleep(sleepTime)

				if requestData != nil {
					req.Body = newByteSliceBody(requestData)
					req.ContentLength = int64(len(requestData))
				}
			}
			resp, err = r.requestPerformer.Do(req)
			if err == nil {
				break
			}

			// Retry needed.

			// Make sure the same connection is not used in the following requests. Most services have
			// several IP addresses and discarding the HTTP and TCP connections with failing service may
			// increase likelihood of succeeding.
			r.requestPerformer.CloseIdleConnections()
		}
	} else {
		err = setContentLength(req)
		if err != nil {
			logctx.WithError(err).Error("Reading request body failed")
			return nil, err
		}
		resp, err = r.requestPerformer.Do(req)
	}

	if err != nil {
		// Also purge connections after failed POSTs and failed last tries
		r.requestPerformer.CloseIdleConnections()
		logctx.WithError(err).Warn("Error performing new request, will report bad gateway")
		return nil, usererror.CreateError(http.StatusBadGateway, "Destination unreachable")
	}

	logctx.Debug("Successfully performed request")
	return resp, nil
}

func retryable(req *http.Request) bool {
	return req.Method != "POST"
}

type createRequestsResult struct {
	mainRequest   *http.Request
	copyRequest   *http.Request
	recompression bool
}

func (r *router) createOutgoingRequests(req *http.Request) (*createRequestsResult, error) {
	logctx := r.logger.WithFields(apexlog.Fields{"func": "router.createOutgoingRequest"})
	fullURL := completeURL(req)
	urlMatch, err := r.createOutgoingURLs(fullURL, req.Method)
	if err != nil {
		logctx.WithError(err).Error("Error creating urlMatch")
		return nil, err
	}
	var mainRequest *http.Request
	logctx.WithFields(apexlog.Fields{"urlMatch.rule": urlMatch.rule, "urlMatch.copyURL": urlMatch.copyURL}).Debug("Got url match")
	recompression := false
	if urlMatch.rule != nil {
		recompression = urlMatch.rule.recompression
		mainRequest, err = r.createProxyRequest(req, urlMatch.rule.internal, urlMatch.rule.hostHeader, urlMatch.url)
		if err != nil {
			logctx.WithError(err).Error("Error creating mainRequest")
			return nil, err
		}
	}
	var copyRequest *http.Request
	if urlMatch.copyURL != nil {
		copyRequest, err = r.createProxyRequest(req, urlMatch.copyRule.internal, urlMatch.copyRule.hostHeader, urlMatch.copyURL)
		if err != nil {
			logctx.WithError(err).Error("Error creating copyRequest")
			return nil, err
		}
	}
	return &createRequestsResult{
		mainRequest:   mainRequest,
		copyRequest:   copyRequest,
		recompression: recompression,
	}, err
}

func filterHeader(originalHeader http.Header, filteredHeaderNames []string) http.Header {
	// Copy first, then filter

	newHeader := make(http.Header, len(originalHeader))

	for hname, hvals := range originalHeader {
		for _, hval := range hvals {
			newHeader.Add(hname, hval)
		}
	}

	for _, hname := range filteredHeaderNames {
		newHeader.Del(hname)
	}

	return newHeader
}

func (r *router) createProxyRequest(req *http.Request, internal bool, hostHeader HostHeader, url *url.URL) (*http.Request, error) {
	logctx := r.logger.WithFields(apexlog.Fields{"func": "router.createProxyRequest", "url": url})
	logctx.Debug("Constructing outgoing request")
	preq, err := http.NewRequestWithContext(req.Context(), req.Method, url.String(), req.Body)
	if err != nil {
		logctx.WithError(err).Error("Error constructing new request")
		return nil, err
	}

	// The router is a proxy, so remove Host and hop-by-hop headers before copying requests
	var nonForwardedHeaderNames = []string{
		"Host",
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	preq.Header = filterHeader(req.Header, nonForwardedHeaderNames)
	switch hostHeader.Behavior {
	case HostHeaderDefault, HostHeaderDestination:
		break
	case HostHeaderOriginal:
		preq.Host = req.Host
	case HostHeaderOverride:
		preq.Host = hostHeader.Override
	}

	readIP := func() string { return util.RequestIP(req) }
	if r.config.RoutingSecrets == nil {
		// If routing secrets are nil, ignore the internal flag and treat all destinations as external
		err = ensureInternalHeaders(preq.Header, false, nil, readIP)
	} else {
		err = ensureInternalHeaders(preq.Header, internal, r.config.RoutingSecrets, readIP)
	}
	return preq, err
}

func ensureInternalHeaders(header http.Header, passHeaders bool, secrets []string, readIP func() string) error {
	oldSecret := header.Get(headerRichieRoutingSecret)
	if oldSecret != "" && !util.StringInSlice(secrets, oldSecret) {
		return usererror.BuildError(usererror.Fields{headerRichieRoutingSecret: oldSecret}).CreateError(http.StatusProxyAuthRequired, "Bad routing secret")
	}

	if passHeaders {
		oldReqID := header.Get(headerRichieRequestID)
		oldOrigIP := header.Get(headerRichieOriginatingIP)

		if oldSecret != "" {
			if oldReqID == "" {
				header.Set(headerRichieRequestID, uuid.NewV4().String())
			}
			if oldOrigIP == "" {
				header.Set(headerRichieOriginatingIP, readIP())
			}
		} else {
			if oldReqID != "" || oldOrigIP != "" {
				errFields := usererror.Fields{
					headerRichieRequestID:     oldReqID,
					headerRichieOriginatingIP: oldOrigIP,
				}
				return usererror.BuildError(errFields).CreateError(http.StatusProxyAuthRequired, "Specifying originating IP or request ID without routing secret not allowed")
			}

			header.Set(headerRichieRequestID, uuid.NewV4().String())
			header.Set(headerRichieOriginatingIP, readIP())
			header.Set(headerRichieRoutingSecret, secrets[0])

		}
	} else {
		header.Del(headerRichieRoutingSecret)
		header.Del(headerRichieRequestID)
		header.Del(headerRichieOriginatingIP)
	}
	return nil
}

type urlMatch struct {
	url      *url.URL
	rule     *Rule
	copyURL  *url.URL
	copyRule *Rule
}

func (r *router) createOutgoingURLs(sourceURL *url.URL, method string) (*urlMatch, error) {
	logctx := r.logger.WithFields(apexlog.Fields{"func": "router.createOutgoingURL", "sourceURL": sourceURL})
	logctx.Debug("Enter")
	reqdst := destinationString(sourceURL)
	logctx = logctx.WithFields(apexlog.Fields{"reqdst": reqdst, "method": method})
	logctx.Debug("Got reqdst")
	ruleMatchResults, err := r.rules.Match(reqdst, method)
	if err != nil {
		logctx.WithError(err).Error("Error matching request to rules")
		return nil, err
	}
	um := new(urlMatch)
	if ruleMatchResults.proxyMatch != nil {
		targetURL, err := url.Parse(ruleMatchResults.proxyMatch.target)
		if err != nil {
			return nil, err
		}

		targetURL.RawQuery = sourceURL.RawQuery
		targetURL.Fragment = sourceURL.Fragment
		um.rule = ruleMatchResults.proxyMatch.rule
		um.url = targetURL
	}

	if ruleMatchResults.copyMatch == nil {
		return um, nil
	}

	copyTargetURL, err := url.Parse(ruleMatchResults.copyMatch.target)
	if err != nil {
		return nil, err
	}

	copyTargetURL.RawQuery = sourceURL.RawQuery
	copyTargetURL.Fragment = sourceURL.Fragment
	um.copyRule = ruleMatchResults.copyMatch.rule
	um.copyURL = copyTargetURL
	return um, nil
}

func completeURL(req *http.Request) *url.URL {
	u2 := *req.URL
	u2.Host = req.Host
	u2.Scheme = scheme(req)
	return &u2
}

func scheme(req *http.Request) string {
	if req.TLS != nil || strings.ToLower(req.Header.Get("X-Forwarded-Proto")) == "https" {
		return "https"
	}
	return "http"
}

func destinationString(u *url.URL) string {
	if u == nil {
		panic("nil url")
	}
	u2 := *u
	u2.Host = util.DropPort(u2.Host)
	u2.RawQuery = ""
	return u2.String()
}
