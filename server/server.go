package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	apexlog "github.com/apex/log"
	"github.com/getsentry/sentry-go"
	"github.com/richiefi/rrrouter/caching"
	"github.com/richiefi/rrrouter/config"
	mets "github.com/richiefi/rrrouter/metrics"
	"github.com/richiefi/rrrouter/proxy"
	"github.com/richiefi/rrrouter/usererror"
	"github.com/richiefi/rrrouter/util"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Run is the main entrypoint used to s the server.
func Run(conf *config.Config, router proxy.Router, logger *apexlog.Logger, cache caching.Cache) {
	smux := http.NewServeMux()
	ConfigureServeMux(smux, conf, router, logger, cache)
	logger.WithFields(apexlog.Fields{"port": conf.Port, "br level": conf.BrotliLevel, "gzip level": conf.GZipLevel}).Debug("Starting listener")
	tlsConfigValid, err := conf.TLSConfigIsValid()
	if err != nil {
		logger.WithField("error", err.Error()).Fatal("Error starting HTTP server")
		return
	}
	addr := ":" + strconv.Itoa(conf.Port)
	readHeaderTimeout := 5 * time.Second
	rht := os.Getenv("SERVER_READ_HEADER_TIMEOUT_SECONDS")
	if v, err := strconv.Atoi(rht); err == nil {
		readHeaderTimeout = time.Duration(v) * time.Second
	}
	readTimeout := 240 * time.Second
	rt := os.Getenv("SERVER_READ_TIMEOUT_SECONDS")
	if v, err := strconv.Atoi(rt); err == nil {
		readTimeout = time.Duration(v) * time.Second
	}
	writeTimeout := 30 * time.Second
	wt := os.Getenv("SERVER_WRITE_TIMEOUT_SECONDS")
	if v, err := strconv.Atoi(wt); err == nil {
		writeTimeout = time.Duration(v) * time.Second
	}
	serv := &http.Server{
		Addr:              addr,
		Handler:           smux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout}
	if tlsConfigValid {
		err = serv.ListenAndServeTLS(conf.TLSCertPath, conf.TLSKeyPath)
	} else {
		err = serv.ListenAndServe()
	}
	if err != nil {
		logger.WithField("error", err).Fatal("Error starting HTTP server")
	}
}

// ConfigureServeMux configures the main mux with a handler for SystemInfo and another for everything else
func ConfigureServeMux(s *http.ServeMux, conf *config.Config, router proxy.Router, logger *apexlog.Logger, cache caching.Cache) {
	s.Handle("/__SYSTEMINFO", basicAuth(showSystemInfo(), conf.AdminName, conf.AdminPass, "Restricted"))
	s.HandleFunc("/__RRROUTER/health", func(w http.ResponseWriter, req *http.Request) {
		if cache != nil {
			if err := cache.HealthCheck(); err != nil {
				w.WriteHeader(503)
				fmt.Fprintf(w, "Unhealthy cache: %v", err)
				return
			}
		}
		fmt.Fprintf(w, "OK")
	})
	s.HandleFunc("/", cachingHandler(router, logger, conf, cache))
}

func cachingHandler(router proxy.Router, logger *apexlog.Logger, conf *config.Config, cache caching.Cache) func(http.ResponseWriter, *http.Request) {
	return func(ow http.ResponseWriter, or *http.Request) {
		m := mets.NewMetrics(or.URL.RequestURI(), nil, nil)
		ctx := context.WithValue(or.Context(), "metrics", m)
		defer m.ReportAndClose(time.Now())
		defer sentry.Recover()

		var cachingFunc func(*http.ResponseWriter, *http.Request, *url.URL, *http.Header, *proxy.RoutingFlavors, bool, bool)
		cachingFunc = func(w *http.ResponseWriter, r *http.Request, overrideURL *url.URL, include *http.Header, frf *proxy.RoutingFlavors, skipRevalidate bool, servedAndRevalidating bool) {
			logctx := logger.WithFields(apexlog.Fields{"url": r.URL, "func": "server.cachingHandler"})
			rf := router.GetRoutingFlavors(r)
			r = preprocessHeaders(r, rf.RequestHeaders)
			shouldSkip := shouldSkipCaching(r.Header, rf)
			if len(rf.CacheId) == 0 && frf != nil {
				rf = *frf
			}
			if include == nil {
				include = &http.Header{}
			}
			if len(rf.CacheId) == 0 || !cache.HasStorage(rf.CacheId) || (r.Method != "GET" && r.Method != "HEAD") {
				reqres, err := router.RouteRequest(ctx, r, overrideURL, rf.Rule)
				if err != nil {
					writeError(*w, err)
					return
				}

				if reqres.RedirectedURL != nil && rf.RestartOnRedirect {
					if urlEquals(reqres.RedirectedURL, r.URL) {
						err = usererror.CreateError(508, "Loop detected")
						writeError(*w, err)
						return
					}
					redirectedUrl := util.RedirectedURL(r, reqres.OriginalURL, reqres.RedirectedURL)
					redirectedUrl.Scheme = reqres.OriginalURL.Scheme
					rr := r.Clone(r.Context())
					rr.URL = redirectedUrl
					rr.Host = redirectedUrl.Host
					rr.RequestURI = reqres.RedirectedURL.RequestURI()
					cachingFunc(w, rr, nil, include, &rf, false, servedAndRevalidating)
					return
				}

				for hname, hvals := range reqres.FinalRoutingFlavors.ResponseHeaders {
					for _, hval := range hvals {
						include.Set(hname, hval)
					}
				}
				include.Set(caching.HeaderRrrouterCacheStatus, "pass")
				_, br, bw, closeWriter := requestHandler(reqres, logger, conf)(*w, r, *include, nil)
				defer reqres.Response.Body.Close()
				if br == nil || bw == nil {
					return
				}
				err = writeBody(br, bw, closeWriter, nil, logctx)
				if err != nil {
					logctx.Infof("writeBodyFunc errored: %v", err)
				}
				return
			}

			keys := caching.KeysFromRequest(ruleDestinationRequest(r, *rf.Rule))
			cr, key, err := cache.Get(ctx, rf.CacheId, rf.ForceRevalidate, skipRevalidate, keys, *w, logger)
			if err != nil {
				cache.Finish(key, logger)
				writeError(*w, err)
				return
			}
			if cr.Reader != nil {
				defer cr.Reader.Close()
			}

			rRange := getRange(r.Header)
			shouldSkipIfNotCached := rRange != nil

			h := (*w).Header()
			if cr.Metadata.Status == 304 {
				include.Set(caching.HeaderRrrouterCacheStatus, "hit")
				h = clearAndCopyHeaders(h, util.AllowHeaders(cr.Metadata.Header, util.HeadersAllowedIn304), *include)
				h = suffixETag(h)
				(*w).WriteHeader(304)
				return
			}

			for hname, hvals := range rf.ResponseHeaders {
				for _, hval := range hvals {
					include.Set(hname, hval)
				}
			}

			switch cr.Kind {
			case caching.NotFoundReader, caching.RevalidatingReader:
				if cr.WaitChan != nil {
					ts := []int{30, 10, 5}
					for i := 0; i < len(ts); i++ {
						select {
						case waitedKeyInfo := <-*cr.WaitChan:
							cr, _, err = cache.Get(ctx, rf.CacheId, rf.ForceRevalidate, waitedKeyInfo.CanUseStale, []caching.Key{waitedKeyInfo.Key}, *w, logger)
							key = waitedKeyInfo.Key
							if err != nil {
								writeError(*w, err)
								return
							}
						case <-time.After(time.Duration(ts[i]) * time.Second):
							writeError(*w, usererror.CreateError(503, "Subresource fetch timed out"))
							return
						}
						if cr.WaitChan == nil {
							break
						}
					}
					if cr.WaitChan != nil {
						// ts's exhausted
						writeError(*w, usererror.CreateError(503, "Subresource fetch timed out"))
						return
					}
					if cr.Reader != nil {
						defer cr.Reader.Close()
					}
				}
			default:
				break
			}

			var found = func(cr caching.CacheResult) {
				if rf.RestartOnRedirect && util.IsRedirect(cr.Metadata.Status) {
					rr, err := requestWithRedirect(r, cr.Metadata.RedirectedURL)
					if err != nil {
						cache.Finish(key, logger)
						writeError(*w, err)
						return
					}
					cachingFunc(w, rr, rr.URL, nil, &rf, false, servedAndRevalidating)
					return
				}

				if servedAndRevalidating {
					cache.Finish(key, logger)
					return
				}

				if len(include.Get(caching.HeaderRrrouterCacheStatus)) == 0 {
					if cr.Stale.IsStale {
						include.Set(caching.HeaderRrrouterCacheStatus, "stale")
					} else {
						include.Set(caching.HeaderRrrouterCacheStatus, "hit")
					}
				} else if include.Get(caching.HeaderRrrouterCacheStatus) == "pass" {
					include.Set(caching.HeaderRrrouterCacheStatus, "hit")
				}
				include.Set(headerAge, strconv.Itoa(int(cr.Age)))

				var statusOverride *int
				if rRange != nil {
					if cr.Metadata.FdSize == 0 {
						msg := fmt.Sprintf("Range requested but resource was zero-length. Key on disk: %v", key.FsName())
						logger.WithField("range", *rRange).WithField("key", key).Warnf(msg)
						sentry.CaptureMessage(msg)
						(*w).WriteHeader(503)
						return
					}
					if cr.Metadata.Status == 200 {
						cl, _ := strconv.Atoi(cr.Metadata.Header.Get("content-length"))
						var s int
						s, include = setRangedHeaders(rRange, int64(cl), cr.Metadata.Status, include)
						if s >= 400 {
							(*w).WriteHeader(s)
							return
						}
						statusOverride = &s
					}
				}

				h = clearAndCopyHeaders(h, cr.Metadata.Header, *include)
				h = suffixETag(h)
				if statusOverride != nil {
					(*w).WriteHeader(*statusOverride)
				} else {
					(*w).WriteHeader(cr.Metadata.Status)
				}

				fatal, err := sendBody(*w, cr.Reader, cr.Metadata.Size, rRange, logctx)
				if err != nil {
					if fatal {
						cache.Finish(key, logger)
					}
				}
				return
			}

			switch cr.Kind {
			case caching.Found:
				found(cr)
				return
			case caching.NotFoundReader, caching.RevalidatingReader:
				if cr.Reader == nil && shouldSkipIfNotCached {
					reqres, err := router.RouteRequest(ctx, r, overrideURL, rf.Rule)
					if err != nil {
						writeError(*w, err)
						return
					}
					for hname, hvals := range reqres.FinalRoutingFlavors.ResponseHeaders {
						for _, hval := range hvals {
							include.Set(hname, hval)
						}
					}
					_, br, bw, closeWriter := requestHandler(reqres, logger, conf)(*w, r, http.Header{caching.HeaderRrrouterCacheStatus: []string{"uncacheable"}}, nil)
					defer reqres.Response.Body.Close()
					if br == nil || bw == nil {
						return
					}
					err = writeBody(br, bw, closeWriter, nil, logctx)
					if err != nil {
						logctx.Infof("writeBodyFunc errored: %v", err)
					}
					return
				} else if cr.Reader == nil {
					msg := fmt.Sprintf("Reader not found after waiting. cr: %v / %v", cr.Kind, cr)
					logctx.Errorf(msg)
					sentry.CaptureMessage(msg)
					return
				}

				if rf.RestartOnRedirect && util.IsRedirect(cr.Metadata.Status) {
					rr, err := requestWithRedirect(r, cr.Metadata.RedirectedURL)
					if err != nil {
						writeError(*w, err)
						return
					}
					cachingFunc(w, rr, rr.URL, include, &rf, false, servedAndRevalidating)
					return
				}

				if cr.Kind == caching.RevalidatingReader {
					include.Set(caching.HeaderRrrouterCacheStatus, "revalidated")
				} else if cr.Kind == caching.NotFoundReader {
					include.Set(caching.HeaderRrrouterCacheStatus, "miss")
				}
				h = clearAndCopyHeaders(h, cr.Metadata.Header, *include)
				h = suffixETag(h)
				(*w).WriteHeader(cr.Metadata.Status)

				_, err := sendBody(*w, cr.Reader, cr.Metadata.Size, rRange, logctx)
				if err != nil {
					writeError(*w, err)
				}
				return
			case caching.NotFoundWriter, caching.RevalidatingWriter:
				if cr.Kind == caching.RevalidatingWriter && cr.Stale.IsStale && cr.Stale.UseWhileRevalidate {
					fd, err := os.Open(cr.Reader.Name())
					if err != nil {
						logctx.WithError(err).Error("Unable to open stale reader fd")
						writeError(*w, err)
						return
					}
					cr.Reader = fd
					cr.Writer.SetClientWritesDisabled()
					found(cr)
					servedAndRevalidating = true
				}

				done := make(chan bool, 1)
				go func() {
					defer func() { done <- true }()
					var errCleanup func()
					defer cache.Finish(key, logger)

					if shouldSkip {
						cr.Writer.SetDiskWritesDisabled()
					}
					if rRange != nil {
						r.Header.Del("range")
					}
					clientRevalidateHeader, _, clientRevalidateValue := util.RevalidateHeaders(r.Header)
					usedRevalidateHeader := ""
					if cr.Kind == caching.RevalidatingWriter {
						clientHeader, _, v := util.RevalidateHeaders(cr.Metadata.Header)
						if len(v) > 0 {
							r.Header.Set(clientHeader, v)
							usedRevalidateHeader = clientHeader
						}
					}
					r = r.WithContext(context.Background()) // Abandon client-bound context as they might disconnect
					reqres, err := router.RouteRequest(ctx, r, overrideURL, rf.Rule)
					if err != nil {
						writeError(*w, err)
						return
					}
					defer reqres.Response.Body.Close()
					rf = reqres.FinalRoutingFlavors
					for hname, hvals := range rf.ResponseHeaders {
						for _, hval := range hvals {
							include.Set(hname, hval)
						}
					}

					var statusOverride *int
					if rRange != nil && reqres.Response.StatusCode == 200 {
						var s int
						s, include = setRangedHeaders(rRange, reqres.Response.ContentLength, reqres.Response.StatusCode, include)
						if s >= 400 {
							(*w).WriteHeader(s)
							return
						}
						statusOverride = &s
					}

					dirs := caching.GetCacheControlDirectives(reqres.Response.Header)
					if len(usedRevalidateHeader) > 0 {
						r.Header.Del(usedRevalidateHeader)
						if reqres.Response.StatusCode == 304 && !dirs.DoNotCache() {
							err := cr.Writer.SetRevalidatedAndClose(reqres.Response.Header)
							if err != nil {
								writeError(*w, err)
								return
							}
							if len(clientRevalidateHeader) > 0 && len(clientRevalidateValue) > 0 {
								r.Header.Set(clientRevalidateHeader, clientRevalidateValue)
							}
							include.Set(caching.HeaderRrrouterCacheStatus, "revalidated")
							if cr.Writer.GetClientWritesDisabled() {
								return
							}
							cachingFunc(w, r, nil, include, &rf, false, servedAndRevalidating)
							return
						}
					}

					if dirs.DoNotCache() || util.IsRedirect(reqres.Response.StatusCode) && reqres.RedirectedURL == nil {
						cache.Finish(key, logger)
						if dirs.DoNotCache() {
							include.Set(caching.HeaderRrrouterCacheStatus, "uncacheable")
						} else {
							include.Set(caching.HeaderRrrouterCacheStatus, "pass")
						}

						_, br, bw, _ := requestHandler(reqres, logger, conf)(*w, r, *include, statusOverride)
						defer reqres.Response.Body.Close()
						if br == nil || bw == nil {
							return
						}
						err = writeBody(br, bw, true, errCleanup, logctx)
						if err != nil {
							logctx.Infof("writeBodyFunc errored: %v", err)
						}
						return
					}

					if cr.Kind == caching.RevalidatingWriter {
						if reqres.Response.StatusCode >= 400 {
							dirs = caching.GetCacheControlDirectives(cr.Metadata.Header)
							if dirs.CanStaleIfError(cr.Age) {
								err := cr.Writer.SetRevalidateErroredAndClose(true)
								if err != nil {
									writeError(*w, err)
									return
								}
								include.Set(caching.HeaderRrrouterCacheStatus, "stale")
								cachingFunc(w, r, nil, include, &rf, true, servedAndRevalidating)
								return
							}
						}
						include.Set(caching.HeaderRrrouterCacheStatus, "revalidated")
					} else {
						include.Set(caching.HeaderRrrouterCacheStatus, "miss")
					}
					if shouldSkip {
						include.Set(caching.HeaderRrrouterCacheStatus, "pass")
					}
					include.Set(headerAge, "0")
					if reqres.RedirectedURL != nil {
						if urlEquals(reqres.RedirectedURL, r.URL) {
							err = usererror.CreateError(508, "Loop detected")
							writeError(*w, err)
							return
						}
						redirectedUrl := util.RedirectedURL(r, reqres.OriginalURL, reqres.RedirectedURL)
						redirectedUrl.Scheme = reqres.OriginalURL.Scheme
						cr.Writer.SetRedirectedURL(redirectedUrl)
						if rf.RestartOnRedirect {
							cr.Writer.SetClientWritesDisabled()
							rr := r.Clone(r.Context())
							rr.URL = redirectedUrl
							rr.Host = redirectedUrl.Host
							rr.RequestURI = reqres.RedirectedURL.RequestURI()
							cachingFunc(w, rr, rr.URL, include, &rf, false, servedAndRevalidating)
							if shouldSkip {
								return
							}
						}
					}
					if dirs.VaryByOrigin() && key.HasOpaqueOrigin() {
						for _, k := range keys {
							if k.HasFullOrigin() {
								err = cr.Writer.ChangeKey(k)
								if err != nil {
									writeError(*w, err)
									return
								}
							}
						}
					}
					errCleanup = func() {
						logger.Infof("errCleanup: %v / %v", key, key.FsName())
						_ = cr.Writer.Delete()
					}
					if shouldSkip {
						if servedAndRevalidating {
							return
						}
						include.Set(caching.HeaderRrrouterCacheStatus, "pass")
						_, br, bw, _ := requestHandler(reqres, logger, conf)(*w, r, *include, statusOverride)
						defer reqres.Response.Body.Close()
						if br == nil || bw == nil {
							return
						}
						err = writeBody(br, bw, true, errCleanup, logctx)
						if err != nil {
							logctx.Infof("writeBodyFunc errored: %v", err)
						}
						return
					}

					crw := cr.Writer
					status, br, bw, _ := requestHandler(reqres, logger, conf)(crw, r, *include, statusOverride)
					defer reqres.Response.Body.Close()
					if br == nil || bw == nil {
						return
					}
					err = writeBody(br, bw, true, errCleanup, logctx)
					if err != nil {
						logctx.Infof("writeBodyFunc errored: %v", err)
						return
					}

					if crw.GetClientWritesDisabled() || servedAndRevalidating {
						return
					}

					fd, err := crw.WrittenFile()
					if err != nil {
						if errCleanup != nil {
							errCleanup()
						}
						logctx.Infof("writeBodyFunc errored: %v", err)
						return
					}
					if fd != nil {
						defer fd.Close()
					}

					fi, err := fd.Stat()
					if err != nil {
						if errCleanup != nil {
							errCleanup()
						}
						logctx.Infof("writeBodyFunc errored: %v", err)
						return
					}

					cw := crw.GetClientWriter()
					cw.WriteHeader(status)
					_, err = sendBody(cw, fd, fi.Size(), rRange, logctx)
					if err != nil {
						logctx.Infof("sendBody errored: %v", err)
						return
					}
					return
				}()
				<-done
			}
		}
		cachingFunc(&ow, or, nil, nil, nil, false, false)
	}
}

func suffixETag(h http.Header) http.Header {
	if etag := h.Get("etag"); len(etag) > 0 {
		h.Set("etag", util.AddETagSuffix(etag))
	}

	return h
}

func ruleDestinationRequest(r *http.Request, rule proxy.Rule) *http.Request {
	return rule.OverrideOnRequest(r.Clone(context.Background()))
}

func preprocessHeaders(r *http.Request, overrides map[string]*string) *http.Request {
	for hname, hval := range overrides {
		if hval == nil {
			r.Header.Del(hname)
		} else {
			r.Header.Set(hname, *hval)
		}
	}

	return r
}

func shouldSkipCaching(h http.Header, rf proxy.RoutingFlavors) bool {
	if len(h.Get("authorization")) > 0 {
		if v, ok := rf.RequestHeaders["authorization"]; ok {
			if v == nil { // Header override is deletion of the `authorization` header
				return false
			}
		}
		return true
	}

	return false
}

func urlEquals(u1 *url.URL, u2 *url.URL) bool {
	if u1 == nil || u2 == nil {
		return false
	}

	return u1.Scheme == u2.Scheme &&
		u1.Opaque == u2.Opaque &&
		((u1.User == nil && u2.User == nil) || (u1.User != nil && u1.User.String() == u2.User.String())) &&
		u1.Host == u2.Host &&
		u1.Path == u2.Path &&
		u1.RawPath == u2.RawPath &&
		u1.ForceQuery == u2.ForceQuery &&
		u1.RawQuery == u2.RawQuery &&
		u1.Fragment == u2.Fragment &&
		u1.RawFragment == u2.RawFragment
}

func requestWithRedirect(r *http.Request, location string) (*http.Request, error) {
	locationUrl, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	rr := r.Clone(r.Context())
	rr.URL = util.RedirectedURL(rr, rr.URL, locationUrl)
	rr.Host = rr.URL.Host
	return rr, nil
}

type BodyWriter func(reader io.ReadCloser, writer io.Writer, closeWriter bool, errCleanup func(), logctx *apexlog.Entry) error

func requestHandler(reqres *proxy.RequestResult, logger *apexlog.Logger, conf *config.Config) func(http.ResponseWriter, *http.Request, http.Header, *int) (int, io.ReadCloser, http.ResponseWriter, bool) {
	return func(w http.ResponseWriter, r *http.Request, alwaysInclude http.Header, statusOverride *int) (int, io.ReadCloser, http.ResponseWriter, bool) {
		logctx := logger.WithFields(apexlog.Fields{"url": r.URL, "func": "server.requestHandler"})
		logctx.Debug("Got request")

		var err error

		logctx = logctx.WithField("proxiedURL", reqres.Response.Request.URL)

		if w == nil {
			// ch19238:
			logctx.Errorf("writer has gone unexpectedly for %v", reqres.Response.Request.URL)
			return 0, nil, nil, false
		}
		header := w.Header()
		header = clearAndCopyHeaders(header, reqres.Response.Header, alwaysInclude)

		var reader io.ReadCloser
		var writer http.ResponseWriter
		closeWriter := false

		if reqres.Recompression.Remove == util.CompressionTypeGzip {
			reader, err = util.NewGzipDecodingReader(reqres.Response.Body)
			if err != nil {
				writeError(w, err)
				return 0, nil, nil, false
			}

			header.Del(headerContentLengthKey)
			header.Del(headerContentEncodingKey)
		} else {
			reader = reqres.Response.Body
		}

		if reqres.Recompression.Add != util.CompressionTypeNone {
			closeWriter = true
			writer, err = NewEncodingResponseWriter(w, reqres.Recompression.Add, conf, logger)
			if err != nil {
				writeError(w, err)
				return 0, nil, nil, false
			}

			header.Del(headerContentLengthKey)
			header.Set(headerContentEncodingKey, util.ContentEncodingFromCompressionType(reqres.Recompression.Add))
			vary := header.Get(headerVaryKey)
			if len(vary) > 0 && !strings.Contains(strings.ToLower(vary), strings.ToLower(headerAcceptEncodingKey)) {
				vary = vary + ", " + headerAcceptEncodingKey
			} else {
				vary = headerAcceptEncodingKey
			}
			header.Set(headerVaryKey, vary)
		} else {
			writer = w
		}

		if etag := header.Get("etag"); len(etag) > 0 {
			header.Set("etag", util.AddETagSuffix(etag))
		}

		status := 0
		if statusOverride != nil {
			status = *statusOverride
		} else {
			status = reqres.Response.StatusCode
		}
		if status == 304 {
			util.AllowHeaders(writer.Header(), util.HeadersAllowedIn304)
			writer.WriteHeader(status)
			return 0, nil, nil, false
		}
		writer.WriteHeader(status)

		return status, reader, writer, closeWriter
	}
}

func clearAndCopyHeaders(h http.Header, originHeader http.Header, alwaysInclude http.Header) http.Header {
	// Remove implicit headers
	for hname := range h {
		h.Del(hname)
	}
	// Copy headers over from the response we received from the proxied server
	for hname, hvals := range originHeader {
		for _, hval := range hvals {
			h.Add(hname, hval)
		}
	}
	// Set any of our own headers
	for hname, hvals := range alwaysInclude {
		for _, hval := range hvals {
			h.Set(hname, hval)
		}
	}

	return h
}

func setRangedHeaders(rr *requestRange, contentLength int64, statusCode int, h *http.Header) (int, *http.Header) {
	if rr == nil || statusCode != 200 || contentLength <= 0 {
		return statusCode, h
	}

	if (rr.s != nil && *rr.s > contentLength-1) || (rr.e != nil && *rr.e > contentLength-1) {
		return 416, h
	}

	h.Set("content-length", strconv.FormatInt(rr.size(contentLength), 10))
	h.Set("content-range", rr.contentRangeValue(contentLength))

	return 206, h
}

func sendBody(w http.ResponseWriter, fd *os.File, size int64, rr *requestRange, logctx *apexlog.Entry) (fatal bool, err error) {
	rf, _ := w.(io.ReaderFrom)

	logctx = logctx.WithField("size", size)
	var start int64
	if rr != nil {
		start = rr.start(size)
		logctx = logctx.WithField("start", start)
		if rr.s != nil {
			logctx = logctx.WithField("s", *rr.s)
		}
		if rr.e != nil {
			logctx = logctx.WithField("e", *rr.e)
		}
	}
	_, err = fd.Seek(start, 0)
	if err != nil {
		logctx.WithField("error", err).Error("Could not seek to desired location")
		return true, err
	}

	readSize := size
	if rr != nil {
		readSize = rr.size(size)
	}

	written, err := rf.ReadFrom(io.LimitReader(fd, readSize))
	if err != nil {
		logctx.WithField("error", err).Info("Writing to client caused an error")
		return false, err
	}
	if written != readSize {
		logctx.WithField("error", err).Error(fmt.Sprintf("Bytes written to client %v did not match %v", written, size))
	}

	return false, err
}

func writeBody(reader io.ReadCloser, writer io.Writer, closeWriter bool, errCleanup func(), logctx *apexlog.Entry) error {
	buf := make([]byte, 32*1024)
	step := func(w io.Writer) (bool, error) {
		rn, rerr := reader.Read(buf)
		if rn > 0 {
			_, werr := w.Write(buf[:rn])
			if werr != nil {
				logctx.WithField("error", werr).Info("Writing of response caused error")
				return false, werr
			}
		}
		if rerr != nil {
			if rerr != io.EOF {
				logctx.WithField("error", rerr).Info("Reading response caused an error")
				return false, rerr
			}
			return false, nil
		}
		return true, nil
	}
	for {
		keepOpen, err := step(writer)
		writer.(http.Flusher).Flush()
		if !keepOpen {
			var closeErr error
			if closeWriter {
				if v, ok := writer.(io.Closer); ok {
					closeErr = v.Close()
					if closeErr != nil {
						logctx.WithField("closeError", closeErr).Info("Closing writer caused an error")
					}
				}
			}
			if (err != nil || closeErr != nil) && errCleanup != nil {
				errCleanup()
			}
			return err
		}
	}
}

const headerContentEncodingKey = "Content-Encoding"
const headerAcceptEncodingKey = "Accept-Encoding"
const headerContentLengthKey = "Content-Length"
const headerVaryKey = "Vary"
const headerAge = "Age"

type EncodingResponseWriter interface {
	http.ResponseWriter
	http.Flusher
}

type encodingResponseWriter struct {
	wrappedWriter      http.ResponseWriter
	closeWrappedWriter bool
	encodingWriter     io.WriteCloser
	log                *apexlog.Logger
}

func (ew *encodingResponseWriter) Header() http.Header {
	return ew.wrappedWriter.Header()
}

func (ew *encodingResponseWriter) Write(ba []byte) (int, error) {
	return ew.encodingWriter.Write(ba)
}

func (ew *encodingResponseWriter) WriteHeader(statusCode int) {
	ew.wrappedWriter.WriteHeader(statusCode)
}

func (ew *encodingResponseWriter) Flush() {
	ew.wrappedWriter.(http.Flusher).Flush()
}

func (ew *encodingResponseWriter) Close() error {
	err := ew.encodingWriter.(io.Closer).Close()
	if err != nil {
		ew.log.Errorf("Closing encodingWriter errored: %v", err)
		return err
	}

	if ew.closeWrappedWriter {
		if v, ok := ew.wrappedWriter.(io.Closer); ok {
			err = v.Close()
			if err != nil {
				ew.log.Errorf("Closing wrappedWriter errored: %v", err)
				return err
			}
		}
	}

	return nil
}

func NewEncodingResponseWriter(w http.ResponseWriter, compressionType util.CompressionType, conf *config.Config, logctx *apexlog.Logger) (EncodingResponseWriter, error) {
	var encodingWriter io.WriteCloser
	closeWrappedWriter := false
	switch compressionType {
	case util.CompressionTypeBrotli:
		encodingWriter = util.NewBrotliEncodingWriter(w, conf.BrotliLevel)
		break
	case util.CompressionTypeGzip:
		var err error
		encodingWriter, err = util.NewGzipEncodingWriter(w, conf.GZipLevel)
		closeWrappedWriter = true
		if err != nil {
			return nil, err
		}
		break
	default:
		return nil, errors.New("Encoding must be specified")
	}
	return &encodingResponseWriter{
		wrappedWriter:      w,
		closeWrappedWriter: closeWrappedWriter,
		encodingWriter:     encodingWriter,
		log:                logctx,
	}, nil
}

func writeError(w http.ResponseWriter, err error) {
	switch err := err.(type) {
	case *usererror.UserError:
		jsonmap := err.JSON()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(err.Code)
		if err := json.NewEncoder(w).Encode(jsonmap); err != nil {
			panic(err)
		}
	case *net.OpError:
		if err.Op != "readfrom" { // Broken pipes are to be expected: error code for others
			w.WriteHeader(500)
		}
	default:
		w.WriteHeader(500)
	}
}

// https://stackoverflow.com/a/39591234
func basicAuth(handler http.HandlerFunc, username string, password string, realm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if username == "" || password == "" {
			// Disable authenticated endpoints if the authorized username or password are not set
			w.WriteHeader(500)
			w.Write([]byte("Endpoint unavailable.\n"))
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 || subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorised.\n"))
			return
		}
		handler(w, r)
	}
}

func showSystemInfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ss := exec.Command("ss", "-tanp")
		output, err := ss.CombinedOutput()
		w.Header().Set("Content-Type", "text/plain")
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(fmt.Sprintf("Error running command: %s", err)))
			return
		}
		w.WriteHeader(200)
		w.Write(output)
	}
}

type requestRange struct {
	s *int64
	e *int64
}

func (rr *requestRange) start(cl int64) int64 {
	if rr.e != nil && rr.s != nil {
		return *rr.s
	} else if rr.e != nil && rr.s == nil {
		return cl + *rr.e
	} else if rr.e == nil && rr.s != nil {
		return *rr.s
	}

	return 0
}

func (rr *requestRange) end(cl int64) int64 {
	if rr.e != nil && rr.s != nil {
		return *rr.e
	} else if rr.e != nil && rr.s == nil {
		return cl - 1
	} else if rr.e == nil && rr.s != nil {
		return cl - 1
	}

	return cl - 1
}

func (rr *requestRange) size(cl int64) int64 {
	if rr.e != nil && rr.s != nil {
		if *rr.s == 0 {
			return *rr.e - *rr.s + 1
		}
		return *rr.e - *rr.s + 1
	} else if rr.e != nil && rr.s == nil {
		end := cl - 1
		start := cl + *rr.e - 1
		return end - start
	} else if rr.e == nil && rr.s != nil {
		return cl - *rr.s
	}

	return cl
}

func (rr *requestRange) contentRangeValue(cl int64) string {
	return fmt.Sprintf("bytes %v-%v/%v", rr.start(cl), rr.end(cl), cl)
}

func getRange(h http.Header) *requestRange {
	s := h.Get("range")
	if len(s) == 0 {
		return nil
	}
	splat := strings.Split(s, "bytes=")
	if len(splat) != 2 {
		return nil
	}
	bs := splat[1]
	var start, end *int64
	st, e := "", ""
	if strings.Index(bs, "-") == 0 {
		st = ""
		e = bs
	} else {
		se := strings.Split(bs, "-")
		if len(se) != 2 {
			return nil
		}
		st = se[0]
		e = se[1]
	}

	if len(st) == 0 {
		start = nil
	} else {
		startInt, err := strconv.ParseInt(st, 10, 64)
		if err != nil {
			return nil
		}
		start = &startInt
	}
	if len(e) == 0 {
		end = nil
	} else {
		endInt, err := strconv.ParseInt(e, 10, 64)
		if err != nil {
			return nil
		}
		end = &endInt
	}

	if end != nil && start != nil {
		if *end < *start {
			return nil
		}
	}

	return &requestRange{start, end}
}
