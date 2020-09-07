package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"

	apexlog "github.com/apex/log"

	"github.com/richiefi/rrrouter/config"
	"github.com/richiefi/rrrouter/proxy"
	"github.com/richiefi/rrrouter/usererror"
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

		w.WriteHeader(reqres.Response.StatusCode)

		// And then the body
		buf := make([]byte, 32*1024)
		step := func(w io.Writer) bool {
			rn, rerr := reqres.Response.Body.Read(buf)
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
			keepOpen := step(w)
			w.(http.Flusher).Flush()
			if !keepOpen {
				return
			}
		}
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
