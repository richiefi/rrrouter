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
	if tlsConfigValid {
		err = http.ListenAndServeTLS(":"+strconv.Itoa(conf.Port), conf.TLSCertPath, conf.TLSKeyPath, smux)
	} else {
		err = http.ListenAndServe(":"+strconv.Itoa(conf.Port), smux)
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

		var cachingFunc func(*http.ResponseWriter, *http.Request, *url.URL, *http.Header, *proxy.RoutingFlavors, bool)
		cachingFunc = func(w *http.ResponseWriter, r *http.Request, overrideURL *url.URL, alwaysInclude *http.Header, frf *proxy.RoutingFlavors, skipRevalidate bool) {
			logctx := logger.WithFields(apexlog.Fields{"url": r.URL, "func": "server.cachingHandler"})
			rf := router.GetRoutingFlavors(r)
			r = preprocessHeaders(r, rf.RequestHeaders)
			shouldSkip := shouldSkipCaching(r.Header, rf)
			if len(rf.CacheId) == 0 && frf != nil {
				rf = *frf
			}
			if alwaysInclude == nil {
				alwaysInclude = &http.Header{}
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
					cachingFunc(w, rr, nil, alwaysInclude, &rf, false)
					return
				}

				for hname, hvals := range reqres.FinalRoutingFlavors.ResponseHeaders {
					for _, hval := range hvals {
						alwaysInclude.Set(hname, hval)
					}
				}
				alwaysInclude.Set(caching.HeaderRrrouterCacheStatus, "pass")
				requestHandler(reqres, logger, conf)(*w, r, *alwaysInclude, nil, writeBody, false, nil)
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

			if cr.Metadata.Status == 304 {
				alwaysInclude.Set(caching.HeaderRrrouterCacheStatus, "hit")
				clearAndCopyHeaders(*w, util.AllowHeaders(cr.Metadata.Header, headersAllowedIn304), *alwaysInclude)
				if etag := (*w).Header().Get("etag"); len(etag) > 0 {
					(*w).Header().Set("etag", util.AddETagSuffix(etag))
				}
				(*w).WriteHeader(304)
				return
			}

			for hname, hvals := range rf.ResponseHeaders {
				for _, hval := range hvals {
					alwaysInclude.Set(hname, hval)
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

			switch cr.Kind {
			case caching.Found:
				if rf.RestartOnRedirect && util.IsRedirect(cr.Metadata.Status) {
					rr, err := requestWithRedirect(r, cr.Metadata.RedirectedURL)
					if err != nil {
						cache.Finish(key, logger)
						writeError(*w, err)
						return
					}
					cachingFunc(w, rr, rr.URL, nil, &rf, false)
					return
				}

				if len(alwaysInclude.Get(caching.HeaderRrrouterCacheStatus)) == 0 {
					if cr.IsStale {
						alwaysInclude.Set(caching.HeaderRrrouterCacheStatus, "stale")
					} else {
						alwaysInclude.Set(caching.HeaderRrrouterCacheStatus, "hit")
					}
				} else if alwaysInclude.Get(caching.HeaderRrrouterCacheStatus) == "pass" {
					alwaysInclude.Set(caching.HeaderRrrouterCacheStatus, "hit")
				}
				alwaysInclude.Set(headerAge, strconv.Itoa(int(cr.Age)))

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
						s, alwaysInclude = setRangedHeaders(rRange, int64(cl), cr.Metadata.Status, alwaysInclude)
						if s >= 400 {
							(*w).WriteHeader(s)
							return
						}
						statusOverride = &s
					}
				}

				clearAndCopyHeaders(*w, cr.Metadata.Header, *alwaysInclude)
				if etag := (*w).Header().Get("etag"); len(etag) > 0 {
					(*w).Header().Set("etag", util.AddETagSuffix(etag))
				}
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
			case caching.NotFoundReader, caching.RevalidatingReader:
				if cr.Reader == nil && shouldSkipIfNotCached {
					reqres, err := router.RouteRequest(ctx, r, overrideURL, rf.Rule)
					if err != nil {
						writeError(*w, err)
						return
					}
					for hname, hvals := range reqres.FinalRoutingFlavors.ResponseHeaders {
						for _, hval := range hvals {
							alwaysInclude.Set(hname, hval)
						}
					}
					requestHandler(reqres, logger, conf)(*w, r, http.Header{caching.HeaderRrrouterCacheStatus: []string{"uncacheable"}}, nil, writeBody, false, nil)
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
					cachingFunc(w, rr, rr.URL, alwaysInclude, &rf, false)
					return
				}

				if cr.Kind == caching.RevalidatingReader {
					alwaysInclude.Set(caching.HeaderRrrouterCacheStatus, "revalidated")
				} else if cr.Kind == caching.NotFoundReader {
					alwaysInclude.Set(caching.HeaderRrrouterCacheStatus, "miss")
				}

				clearAndCopyHeaders(*w, cr.Metadata.Header, *alwaysInclude)
				if etag := (*w).Header().Get("etag"); len(etag) > 0 {
					(*w).Header().Set("etag", util.AddETagSuffix(etag))
				}
				(*w).WriteHeader(cr.Metadata.Status)

				_, err := sendBody(*w, cr.Reader, cr.Metadata.Size, rRange, logctx)
				if err != nil {
					writeError(*w, err)
				}
				return
			case caching.NotFoundWriter, caching.RevalidatingWriter:
				var writeBodyFunc BodyWriter
				var writer http.ResponseWriter
				var errCleanup func()
				defer cache.Finish(key, logger)

				if shouldSkip {
					cr.Writer.SetDiskWritesDisabled()
				}
				if rRange != nil {
					r.Header.Del("range")
				}
				revalidatedWithHeader := ""
				if cr.Kind == caching.RevalidatingWriter {
					if etag := cr.Metadata.Header.Get("etag"); len(etag) > 0 {
						r.Header.Set("if-none-match", etag)
						revalidatedWithHeader = "if-none-match"
					} else if lastModified := cr.Metadata.Header.Get("last-modified"); len(lastModified) > 0 {
						r.Header.Set("if-modified-since", lastModified)
						revalidatedWithHeader = "if-modified-since"
					}
				} else if cr.Kind == caching.NotFoundWriter {
					r.Header.Del("if-none-match")
					r.Header.Del("if-modified-since")
				}
				reqres, err := router.RouteRequest(ctx, r, overrideURL, rf.Rule)
				if err != nil {
					writeError(*w, err)
					return
				}
				defer reqres.Response.Body.Close()
				rf = reqres.FinalRoutingFlavors
				for hname, hvals := range rf.ResponseHeaders {
					for _, hval := range hvals {
						alwaysInclude.Set(hname, hval)
					}
				}
				if len(revalidatedWithHeader) > 0 {
					r.Header.Del(revalidatedWithHeader)
					if reqres.Response.StatusCode == 304 {
						err := cr.Writer.SetRevalidatedAndClose()
						if err != nil {
							writeError(*w, err)
							return
						}
						alwaysInclude.Set(caching.HeaderRrrouterCacheStatus, "revalidated")
						cachingFunc(w, r, nil, alwaysInclude, &rf, false)
						return
					}
				}
				var statusOverride *int
				if rRange != nil && reqres.Response.StatusCode == 200 {
					var s int
					s, alwaysInclude = setRangedHeaders(rRange, reqres.Response.ContentLength, reqres.Response.StatusCode, alwaysInclude)
					if s >= 400 {
						(*w).WriteHeader(s)
						return
					}
					statusOverride = &s
				}
				dirs := caching.GetCacheControlDirectives(reqres.Response.Header)
				if dirs.DoNotCache() {
					alwaysInclude.Set(caching.HeaderRrrouterCacheStatus, "uncacheable")
					cache.Finish(key, logger)
					writeBodyFunc = writeBody
					writer = *w
				} else if reqres.RedirectedURL == nil && util.IsRedirect(reqres.Response.StatusCode) {
					alwaysInclude.Set(caching.HeaderRrrouterCacheStatus, "pass")
					cache.Finish(key, logger)
					writeBodyFunc = writeBody
					writer = *w
				} else {
					if cr.Kind == caching.RevalidatingWriter {
						if reqres.Response.StatusCode >= 400 {
							dirs = caching.GetCacheControlDirectives(cr.Metadata.Header)
							if dirs.CanStaleIfError(cr.Age) {
								err := cr.Writer.SetRevalidateErroredAndClose(true)
								if err != nil {
									writeError(*w, err)
									return
								}
								alwaysInclude.Set(caching.HeaderRrrouterCacheStatus, "stale")
								cachingFunc(w, r, nil, alwaysInclude, &rf, true)
								return
							}
						}
						alwaysInclude.Set(caching.HeaderRrrouterCacheStatus, "revalidated")
					} else {
						alwaysInclude.Set(caching.HeaderRrrouterCacheStatus, "miss")
					}
					if shouldSkip {
						alwaysInclude.Set(caching.HeaderRrrouterCacheStatus, "pass")
					}
					alwaysInclude.Set(headerAge, "0")
					clientWritesDisabled := false
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
							clientWritesDisabled = true
							rr := r.Clone(r.Context())
							rr.URL = redirectedUrl
							rr.Host = redirectedUrl.Host
							rr.RequestURI = reqres.RedirectedURL.RequestURI()
							cachingFunc(w, rr, rr.URL, alwaysInclude, &rf, false)
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
					if shouldSkip {
						if clientWritesDisabled {
							return
						}
						alwaysInclude.Set(caching.HeaderRrrouterCacheStatus, "pass")
						writeBodyFunc = writeBody
						writer = *w
					} else {
						writeBodyFunc = makeCachingWriteBody(rRange)
						writer = cr.Writer
					}
					errCleanup = func() {
						logger.Infof("errCleanup: %v / %v", key, key.FsName())
						_ = cr.Writer.Delete()
					}
				}

				requestHandler(reqres, logger, conf)(writer, r, *alwaysInclude, statusOverride, writeBodyFunc, true, errCleanup)
				return
			}
		}
		cachingFunc(&ow, or, nil, nil, nil, false)
	}
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

func requestHandler(reqres *proxy.RequestResult, logger *apexlog.Logger, conf *config.Config) func(http.ResponseWriter, *http.Request, http.Header, *int, BodyWriter, bool, func()) {
	return func(w http.ResponseWriter, r *http.Request, alwaysInclude http.Header, statusOverride *int, writeBodyFunc BodyWriter, forceCloseWriter bool, errCleanup func()) {
		logctx := logger.WithFields(apexlog.Fields{"url": r.URL, "func": "server.requestHandler"})
		logctx.Debug("Got request")

		var err error
		defer reqres.Response.Body.Close()
		logctx = logctx.WithField("proxiedURL", reqres.Response.Request.URL)

		if w == nil {
			// ch19238:
			logctx.Errorf("writer has gone unexpectedly for %v", reqres.Response.Request.URL)
			return
		}
		header := clearAndCopyHeaders(w, reqres.Response.Header, alwaysInclude)

		var reader io.ReadCloser
		var writer http.ResponseWriter
		closeWriter := false

		if reqres.Recompression.Remove == util.CompressionTypeGzip {
			reader, err = util.NewGzipDecodingReader(reqres.Response.Body)
			if err != nil {
				writeError(w, err)
				return
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
				return
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
			util.AllowHeaders(writer.Header(), headersAllowedIn304)
			writer.WriteHeader(status)
			return
		}
		writer.WriteHeader(status)

		err = writeBodyFunc(reader, writer, closeWriter || forceCloseWriter, errCleanup, logctx)
		if err != nil {
			logctx.Infof("writeBodyFunc errored: %v", err)
		}
	}
}

func clearAndCopyHeaders(w http.ResponseWriter, originHeader http.Header, alwaysInclude http.Header) http.Header {
	// Remove implicit headers
	header := w.Header()
	for hname := range header {
		header.Del(hname)
	}

	// Copy headers over from the response we received from the proxied server
	for hname, hvals := range originHeader {
		for _, hval := range hvals {
			header.Add(hname, hval)
		}
	}
	// Set any of our own headers
	for hname, hvals := range alwaysInclude {
		for _, hval := range hvals {
			header.Set(hname, hval)
		}
	}
	return header
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

func makeCachingWriteBody(rr *requestRange) BodyWriter {
	return func(reader io.ReadCloser, writer io.Writer, closeWriter bool, errCleanup func(), logctx *apexlog.Entry) error {
		err := writeBody(reader, writer, closeWriter, errCleanup, logctx)
		if err != nil {
			return err
		}

		var crw caching.CachingResponseWriter
		var ok bool
		crw, ok = writer.(caching.CachingResponseWriter)
		if !ok {
			var erw *encodingResponseWriter
			if erw, ok = writer.(*encodingResponseWriter); ok {
				if erw.wrappedWriter != nil {
					crw, ok = erw.wrappedWriter.(caching.CachingResponseWriter)
				}
			}
		}
		if !ok {
			if errCleanup != nil {
				errCleanup()
			}
			panic(fmt.Sprintf("Caching writer missing"))
		}

		if crw.GetClientWritesDisabled() {
			return nil
		}

		fd, err := crw.WrittenFile()
		if err != nil {
			if errCleanup != nil {
				errCleanup()
			}
			return err
		}
		if fd != nil {
			defer fd.Close()
		}

		fi, err := fd.Stat()
		if err != nil {
			if errCleanup != nil {
				errCleanup()
			}
			return err
		}

		_, err = sendBody(crw.GetClientWriter(), fd, fi.Size(), rr, logctx)
		if err != nil {
			return err
		}

		return nil
	}
}

var headerContentEncodingKey = "Content-Encoding"
var headerAcceptEncodingKey = "Accept-Encoding"
var headerContentLengthKey = "Content-Length"
var headerVaryKey = "Vary"
var headerAge = "Age"
var headersAllowedIn304 = []string{"cache-control", "content-location", "date", "etag", "last-modified", "expires", "vary", "richie-edge-cache"}

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
