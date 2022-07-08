package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"sort"
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

type RequestResult struct {
	Response            *http.Response
	Recompression       util.Recompression
	OriginalURL         *url.URL
	RedirectedURL       *url.URL
	FinalRoutingFlavors RoutingFlavors
}

// Router is the meat of rrrouter
//type Router interface {
//	RouteRequest(context.Context, *http.Request, *url.URL, *Rule) (*RequestResult, error)
//	GetRoutingFlavors(*http.Request) RoutingFlavors
//	SetRules(*Rules)
//}

type RoutingFlavors struct {
	CacheId           string
	ForceRevalidate   int
	RestartOnRedirect bool
	RequestHeaders    map[string]*string
	ResponseHeaders   http.Header
	Rule              *Rule
}

func headersEqual(h1 http.Header, h2 http.Header) bool {
	if len(h1) != len(h2) {
		return false
	}
	keys := []string{}
	for k, _ := range h1 {
		keys = append(keys, k)
	}
	for _, k := range keys {
		vv1 := h1.Values(k)
		sort.Strings(vv1)
		vv2 := h2.Values(k)
		sort.Strings(vv2)
		if len(vv1) != len(vv2) {
			return false
		}
		for i := range vv1 {
			if vv1[i] != vv2[i] {
				return false
			}
		}
	}

	return true
}

type requestPerformer interface {
	Do(req *http.Request) (resp *http.Response, err error)
	CloseIdleConnections()
}

type roundTripPerformer struct {
	roundTripper *http.Transport
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

// Router is the meat of rrrouter
type Router struct {
	rules            *Rules
	logger           *apexlog.Logger
	config           *config.Config
	requestPerformer requestPerformer
}

// NewRouter creates a new router with given Rules
func NewRouter(rules *Rules, logger *apexlog.Logger, conf *config.Config) *Router {
	// Same values as in DefaultTransport, with the addition of
	// increased MaxIdleConnsPerHost (it defaults to DefaultMaxIdleConnsPerHost)
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
			Resolver: &net.Resolver{
				PreferGo: true,
			},
		}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxConnsPerHost:       1000,
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   1000,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	}

	return &Router{
		rules:            rules,
		logger:           logger,
		config:           conf,
		requestPerformer: &roundTripPerformer{roundTripper: transport},
	}
}

// NewRouterWithPerformer is NewRouter with a specific requestPerformer
func NewRouterWithPerformer(rules *Rules, logger *apexlog.Logger, conf *config.Config, performer requestPerformer) *Router {
	return &Router{
		rules:            rules,
		logger:           logger,
		config:           conf,
		requestPerformer: performer,
	}
}

func (r *Router) RouteRequest(ctx context.Context, req *http.Request, overrideURL *url.URL, fallbackRule *Rule) (*RequestResult, error) {
	logctx := r.logger.WithFields(apexlog.Fields{"func": "router.RouteRequest"})
	logctx.Debug("Enter")
	urlMatch, err := r.createUrlMatch(req, nil, logctx)
	if err != nil {
		return nil, err
	}

	return r.routeRequest(ctx, urlMatch, req, overrideURL, fallbackRule, logctx)
}

func (r *Router) createUrlMatch(req *http.Request, overrideRules *Rules, logctx *apexlog.Entry) (*urlMatch, error) {
	fullURL := completeURL(req)
	urlMatch, err := r.createOutgoingURLs(fullURL, req.Method, overrideRules)
	if err != nil {
		logctx.WithError(err).Error("Error creating urlMatch")
		return nil, err
	}
	return urlMatch, nil
}

func (r *Router) routeRequest(ctx context.Context, urlMatch *urlMatch, req *http.Request, overrideURL *url.URL, fallbackRule *Rule, logctx *apexlog.Entry) (*RequestResult, error) {
	requestsResult, err := r.createOutgoingRequests(urlMatch, req, overrideURL, fallbackRule)
	if err != nil {
		logctx.WithError(err).Error("error creating outgoing request")
		return nil, err
	}

	twoTargets := requestsResult.copyRequest != nil && requestsResult.mainRequest != nil
	canRetry := retryable(req)
	retryRule := requestsResult.retryRule

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
		var copyResp *http.Response
		copyResp, err = r.performRequest(requestsResult.copyRequest, bodyData, retryRule == nil)
		if err != nil {
			logctx.WithError(err).Error("Error performing copy request")
		} else {
			logctx.WithFields(apexlog.Fields{"copyRequest.URL": requestsResult.copyRequest.URL, "copyResponse.Status": copyResp.Status}).Info("Copy request performed")
			defer copyResp.Body.Close()
		}
	}

	var mainResp *http.Response
	var redirectedURL *url.URL
	st := time.Now()
	if requestsResult.mainRequest != nil {
		mainResp, err = r.performRequest(requestsResult.mainRequest, bodyData, retryRule == nil)
		if mainResp != nil && util.IsRedirect(mainResp.StatusCode) {
			redirectedURL, err = url.Parse(mainResp.Header.Get("location"))
			if err != nil {
				logctx.WithError(err).Errorf("Error parsing redirection")
				mainResp.Body.Close()
				return nil, err
			}
		}
		if (retryRule != nil && err != nil) || (retryRule != nil && mainResp != nil && is4xxError(mainResp.StatusCode)) {
			overrideRules := &Rules{
				rules:  []*Rule{requestsResult.retryRule},
				logger: nil,
			}
			if mainResp != nil {
				defer mainResp.Body.Close()
			}
			urlMatch, err := r.createUrlMatch(req, overrideRules, logctx)
			if err != nil {
				return nil, err
			}
			return r.routeRequest(ctx, urlMatch, req, nil, nil, logctx)
		} else if err != nil {
			logctx.WithField("url", req.RequestURI).WithField("time", time.Now().Sub(st)).WithError(err).Error("Error performing main request")
			return nil, err
		}
		logctx.Debug("Successfully performed request")
	} else {
		return nil, usererror.BuildError(usererror.Fields{"URL": req.URL.String()}).CreateError(http.StatusNotFound, "No destination found for request target")
	}

	recompression := util.Recompression{Add: util.CompressionTypeNone, Remove: util.CompressionTypeNone}
	if requestsResult.recompression && canTransform(mainResp.Header.Get("cache-control")) {
		recompression = util.GetRecompression(req.Header.Get("Accept-Encoding"), mainResp.Header.Get("Content-Encoding"), mainResp.Header.Get("Content-Type"))
	}

	return &RequestResult{
		Response:            mainResp,
		Recompression:       recompression,
		OriginalURL:         requestsResult.mainRequest.URL,
		RedirectedURL:       redirectedURL,
		FinalRoutingFlavors: r.getRoutingFlavors(requestsResult.rule),
	}, nil
}

func (r *Router) follow(ctx context.Context, req *http.Request, requestData []byte, retryAllowed bool) (*http.Response, *url.URL, error) {
	logctx := r.logger.WithFields(apexlog.Fields{"func": "router.follow"})

	var redirectedURL *url.URL
	for redirections := 0; redirections < 15; redirections += 1 {
		resp, err := r.performRequest(req, requestData, retryAllowed)
		if err != nil {
			return nil, nil, err
		}
		if util.IsRedirect(resp.StatusCode) {
			logctx.Debugf("Following to %v", resp.Header.Get("location"))
			redirectedURL, err = url.Parse(resp.Header.Get("location"))
			if err != nil {
				logctx.WithError(err).Errorf("Error parsing redirection")
				return nil, nil, err
			}

			req.URL = util.RedirectedURL(req, req.URL, redirectedURL)
			req.Host = req.URL.Host
			requestData = nil
		} else {
			return resp, redirectedURL, err
		}
	}

	logctx.Errorf("Too many redirections, giving up. Final URL: %v", redirectedURL.String())
	return nil, nil, nil
}

func canTransform(cc string) bool {
	if len(cc) > 0 {
		return strings.Index(strings.ToLower(cc), "no-transform") == -1
	}

	return true
}

func (r *Router) GetRoutingFlavors(req *http.Request) RoutingFlavors {
	rf := RoutingFlavors{}
	ruleMatchResults, err := r.createRuleMatchResults(req, nil)
	if err != nil {
		return rf
	}
	if ruleMatchResults.proxyMatch != nil && ruleMatchResults.proxyMatch.rule != nil {
		return r.getRoutingFlavors(ruleMatchResults.proxyMatch.rule)
	} else {
		return rf
	}
}

func (r *Router) getRoutingFlavors(rule *Rule) RoutingFlavors {
	rf := RoutingFlavors{}
	rf.CacheId = rule.cacheId
	rf.ForceRevalidate = rule.forceRevalidate
	rf.RestartOnRedirect = rule.restartOnRedirect
	h := http.Header{}
	if len(rule.responseHeaders) > 0 {
		for k, v := range rule.responseHeaders {
			h.Set(k, v)
		}
	}
	if len(h) > 0 {
		rf.ResponseHeaders = h
	}
	rf.RequestHeaders = rule.requestHeaders
	rf.Rule = rule

	return rf
}

func (r *Router) createRuleMatchResults(req *http.Request, overrideRules *Rules) (*RuleMatchResults, error) {
	reqdst := destinationString(completeURL(req))
	var ruleMatchResults *RuleMatchResults
	var err error
	if overrideRules != nil {
		ruleMatchResults, err = overrideRules.Match(reqdst, req.Method)
	} else {
		ruleMatchResults, err = r.rules.Match(reqdst, req.Method)
	}

	return ruleMatchResults, err
}

func (r *Router) SetRules(rules *Rules) {
	r.logger.Debugf("Refreshing rules\n")
	r.rules = rules
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

func (r *Router) performRequest(req *http.Request, requestData []byte, retryAllowed bool) (*http.Response, error) {
	logctx := r.logger.WithFields(apexlog.Fields{"func": "router.performRequest"})
	logctx.Debug("Enter")

	var err error
	var resp *http.Response
	if retryable(req) && retryAllowed {
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
			if errors.Is(err, context.Canceled) {
				if resp != nil {
					resp.Body.Close()
				}
				return nil, err
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
		if resp != nil {
			resp.Body.Close()
		}
		// Also purge connections after failed POSTs and failed last tries
		r.requestPerformer.CloseIdleConnections()
		if isClientClose(err) {
			logctx.WithError(err).Warn("Error performing new request, will report client closed connection")
			return nil, usererror.CreateError(499, "Client closed connection")
		} else {
			logctx.WithError(err).Warn("Error performing new request, will report bad gateway")
			return nil, usererror.CreateError(http.StatusBadGateway, "Destination unreachable")
		}
	}

	logctx.Debug("Successfully performed request")
	return resp, nil
}

func isClientClose(err error) bool {
	return err.Error() == "context canceled"
}

func retryable(req *http.Request) bool {
	return req.Method != "POST"
}

type createRequestsResult struct {
	mainRequest       *http.Request
	copyRequest       *http.Request
	recompression     bool
	restartOnRedirect bool
	cacheId           string
	rule              *Rule
	retryRule         *Rule
}

func (r *Router) RuleForCaching(req *http.Request) (*Rule, error) {
	fullURL := completeURL(req)
	urlMatch, err := r.createOutgoingURLs(fullURL, req.Method, nil)
	if err != nil {
		return nil, err
	}
	if urlMatch.rule != nil {
		return urlMatch.rule, nil
	}

	return nil, nil
}

func (r *Router) createOutgoingRequests(urlMatch *urlMatch, req *http.Request, overrideURL *url.URL, fallbackRule *Rule) (*createRequestsResult, error) {
	logctx := r.logger.WithFields(apexlog.Fields{"func": "router.createOutgoingRequest"})
	var mainRequest *http.Request
	var err error
	logctx.WithFields(apexlog.Fields{"urlMatch.rule": urlMatch.rule, "urlMatch.copyURL": urlMatch.copyURL}).Debug("Got url match")
	recompression := false
	restartOnRedirect := false
	cacheId := ""
	var rule *Rule
	var retryRule *Rule
	useReqURL := false
	if urlMatch.rule != nil {
		rule = urlMatch.rule
	} else {
		rule = fallbackRule
		useReqURL = true
	}
	if rule != nil {
		recompression = rule.recompression
		var u *url.URL
		if overrideURL != nil {
			u = overrideURL
		} else if useReqURL {
			u = req.URL
		} else {
			u = urlMatch.url
		}
		mainRequest, err = r.createProxyRequest(req, rule.internal, rule.hostHeader, u)
		if err != nil {
			logctx.WithError(err).Error("Error creating mainRequest")
			return nil, err
		}
		restartOnRedirect = rule.restartOnRedirect
		cacheId = rule.cacheId
		retryRule = rule.retryRule
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
		mainRequest:       mainRequest,
		copyRequest:       copyRequest,
		recompression:     recompression,
		restartOnRedirect: restartOnRedirect,
		cacheId:           cacheId,
		retryRule:         retryRule,
		rule:              rule,
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

func (r *Router) createProxyRequest(req *http.Request, internal bool, hostHeader HostHeader, url *url.URL) (*http.Request, error) {
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

func (r *Router) createOutgoingURLs(sourceURL *url.URL, method string, overrideRules *Rules) (*urlMatch, error) {
	logctx := r.logger.WithFields(apexlog.Fields{"func": "router.createOutgoingURL", "sourceURL": sourceURL})
	logctx.Debug("Enter")
	reqdst := destinationString(sourceURL)
	logctx = logctx.WithFields(apexlog.Fields{"reqdst": reqdst, "method": method})
	logctx.Debug("Got reqdst")
	var ruleMatchResults *RuleMatchResults
	var err error
	if overrideRules != nil {
		ruleMatchResults, err = overrideRules.Match(reqdst, method)
	} else {
		ruleMatchResults, err = r.rules.Match(reqdst, method)
	}

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
	//u2.RawQuery = ""
	return u2.String()
}

func is4xxError(s int) bool {
	return s >= 400 && s <= 499
}
