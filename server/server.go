package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"

	apexlog "github.com/apex/log"

	"github.com/richiefi/rrrouter/config"
	"github.com/richiefi/rrrouter/proxy"
	"github.com/richiefi/rrrouter/usererror"
	"github.com/richiefi/rrrouter/util"
)

// Run is the main entrypoint used to start the server.
func Run(conf *config.Config, router proxy.Router, logger *apexlog.Logger) {
	smux := http.NewServeMux()
	ConfigureServeMux(smux, conf, router, logger)
	logger.WithField("port", conf.Port).Debug("Starting listener")
	err := http.ListenAndServe(":"+strconv.Itoa(conf.Port), smux)
	if err != nil {
		logger.WithField("error", err).Fatal("Error starting HTTP server")
	}
}

// ConfigureServeMux configures the main mux with a handler for SystemInfo and another for everything else
func ConfigureServeMux(s *http.ServeMux, conf *config.Config, router proxy.Router, logger *apexlog.Logger) {
	s.Handle("/__SYSTEMINFO", basicAuth(showSystemInfo(), conf.AdminName, conf.AdminPass, "Restricted"))
	s.HandleFunc("/__RRROUTER/health", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "OK")
	})
	s.HandleFunc("/", requestHandler(router, logger))
}

func requestHandler(router proxy.Router, logger *apexlog.Logger) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		logctx := logger.WithFields(apexlog.Fields{"url": r.URL, "func": "server.requestHandler"})
		logctx.Debug("Got request")
		reqres, err := router.RouteRequest(r)
		if err != nil {
			writeError(w, err)
			return
		}
		defer reqres.Response.Body.Close()
		logctx = logctx.WithField("proxiedURL", reqres.Response.Request.URL)

		// Remove implicit headers
		header := w.Header()
		for hname := range header {
			header.Del(hname)
		}

		// Copy headers over from the response we received from the proxied server
		for hname, hvals := range reqres.Response.Header {
			for _, hval := range hvals {
				header.Add(hname, hval)
			}
		}

		var reader io.ReadCloser
		var writer http.ResponseWriter
		if reqres.AddCompressionType != util.CompressionTypeNone {
			if reqres.Response.Header.Get(headerContentEncodingKey) == "gzip" {
				reader, err = util.NewGzipDecodingReader(reqres.Response.Body)
				if (err != nil) {
					writeError(w, err)
					return
				}
			} else {
				reader = reqres.Response.Body
			}

			writer = NewEncodingResponseWriter(w, reqres.AddCompressionType)
			header.Del(headerContentLengthKey)
			header.Set(headerContentEncodingKey, util.ContentEncodingFromCompressionType(reqres.AddCompressionType))
			vary := header.Get(headerVaryKey)
			if len(vary) > 0 && ! strings.Contains(strings.ToLower(vary), strings.ToLower(headerContentEncodingKey)) {
				vary = vary + ", " + headerContentEncodingKey
			} else {
				vary = headerContentEncodingKey
			}
			header.Set(headerVaryKey, vary)
		} else {
			reader = reqres.Response.Body
			writer = w
		}

		w.WriteHeader(reqres.Response.StatusCode)

		// And then the body
		buf := make([]byte, 32*1024)
		step := func(w io.Writer) bool {
			rn, rerr := reader.Read(buf)
			if rn > 0 {
				_, werr := w.Write(buf[:rn])
				if werr != nil {
					logctx.WithField("error", werr).Info("Writing of response caused error")
					return false
				}
			}
			if rerr != nil {
				if rerr != io.EOF {
					logctx.WithField("error", rerr).Info("Reading response caused an error")
				}
				return false
			}
			return true
		}
		for {
			keepOpen := step(writer)
			writer.(http.Flusher).Flush()
			if !keepOpen {
				return
			}
		}
	}
}

var headerContentEncodingKey = "Content-Encoding"
var headerContentLengthKey   = "Content-Length"
var headerVaryKey            = "Vary"

type EncodingResponseWriter interface {
	http.ResponseWriter
	http.Flusher
}

type encodingResponseWriter struct {
	wrappedWriter   http.ResponseWriter
	encodingWriter  io.Writer
}

func (ew *encodingResponseWriter) Header() (http.Header) {
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

func NewEncodingResponseWriter(w http.ResponseWriter, compressionType util.CompressionType) EncodingResponseWriter {
	var encodingWriter io.Writer
	switch compressionType {
	case util.CompressionTypeBrotli:
		encodingWriter = util.NewBrotliEncodingWriter(w)
		break
	case util.CompressionTypeGzip:
		encodingWriter = util.NewGzipEncodingWriter(w)
		break
	default:
		encodingWriter = w
	}
	return &encodingResponseWriter{
		wrappedWriter: w,
		encodingWriter: encodingWriter,
	}
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
