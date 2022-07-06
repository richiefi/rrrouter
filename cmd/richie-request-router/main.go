package main

import (
	"errors"
	"fmt"
	"github.com/getsentry/sentry-go"
	"github.com/richiefi/rrrouter/caching"
	"github.com/richiefi/rrrouter/util"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "net/http/pprof"

	"github.com/alecthomas/kong"
	apexlog "github.com/apex/log"
	apexlogjson "github.com/apex/log/handlers/json"
	apexlogtext "github.com/apex/log/handlers/text"
	"github.com/richiefi/rrrouter/config"
	"github.com/richiefi/rrrouter/proxy"
	"github.com/richiefi/rrrouter/server"
)

// StartCmd is the rrrouter server mode configuration structure
type StartCmd config.Config

type checkMappingCmd struct {
	MappingURL  string `help:"URL to remotely stored mapping" xor:"mappingsource" env:"MAPPING_URL"`
	MappingFile string `type:"existingfile" help:"Path to local mapping" xor:"mappingsource" env:"MAPPING_FILE"`
}

type checkQueryCmd struct {
	MappingURL  string `help:"URL to remotely stored mapping" xor:"mappingsource" env:"MAPPING_URL"`
	MappingFile string `type:"existingfile" help:"Path to local mapping" xor:"mappingsource" env:"MAPPING_FILE"`
	Method      string `kong:"required,help='HTTP method'"`
	Query       string `kong:"required,help='HTTP query'"`
}

var cli struct {
	Debug        bool            `help:"Debug mode: colorful, non-JSON logging" env:"RRROUTER_DEBUG"`
	Start        StartCmd        `kong:"cmd,help='Start the router',default='1'"`
	CheckMapping checkMappingCmd `kong:"cmd,help='Check mapping configuration'"`
	CheckQuery   checkQueryCmd   `kong:"cmd,help='Check the target of a single route'"`
}

type cliContext struct {
	Debug bool
}

func main() {
	ctx := kong.Parse(&cli,
		kong.Name("rrrouter"),
		kong.Description("Richie Request Router"))

	if len(os.Getenv("SENTRY_DSN")) > 0 {
		err := sentry.Init(sentry.ClientOptions{
			Release:          os.Getenv("IMAGE"),
			AttachStacktrace: true,
		})
		if err != nil {
			log.Fatalf("sentry.Init: %s", err)
		}
		defer sentry.Flush(2 * time.Second)
	}

	go func() {
		http.ListenAndServe(":7070", nil)
	}()

	err := ctx.Run(&cliContext{Debug: cli.Debug})
	ctx.FatalIfErrorf(err)
}

var gMappingURL string
var gMappingFile string
var gMappingChecksum string

// Run starts the server
func (s *StartCmd) Run(ctx *cliContext) error {
	c := config.Config(*s)

	logger := createLogger(ctx.Debug)
	mappingData, err := readMapping(s.MappingURL, s.MappingFile)
	if err != nil {
		return err
	}
	rules, err := proxy.ParseRules(mappingData, logger)
	if err != nil {
		return err
	}
	logger.WithField("rules", rules).Debug("Parsed rules")
	router := proxy.NewRouter(rules, logger, &c)

	cfgs, err := caching.ParseStorageConfigs(mappingData)
	if err != nil {
		return err
	}
	ca := caching.NewCacheWithOptions(cfgs,
		logger,
		func() time.Time {
			return time.Now()
		},
	)
	gMappingURL = s.MappingURL
	gMappingFile = s.MappingFile
	gMappingChecksum = util.SHA1String(mappingData)
	reloadChan := make(chan bool, 1)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	if c.MappingCheckInterval > 0 {
		go periodicReloader(reloadChan, c.MappingCheckInterval)
	}
	go signalReloader(sigChan, reloadChan)
	go configReloader(reloadChan, router, ca, logger)

	server.Run(&c, router, logger, ca)

	return nil
}

func configReloader(c chan bool, router proxy.Router, cache caching.Cache, logger *apexlog.Logger) {
	for {
		<-c
		mappingData, err := readMapping(gMappingURL, gMappingFile)
		if err != nil {
			logger.Errorf("ConfigReloader: caught error reading mapping. URL: %v / file: %v: %v", gMappingURL, gMappingFile, err)
			continue
		}
		mc := util.SHA1String(mappingData)
		if gMappingChecksum == mc {
			continue
		}
		rules, err := proxy.ParseRules(mappingData, logger)
		if err != nil {
			logger.Errorf("ConfigReloader: caught error parsing rules when refreshing config: %v", err)
			continue
		}
		router.SetRules(rules)
		cfgs, err := caching.ParseStorageConfigs(mappingData)
		if err != nil {
			logger.Errorf("ConfigReloader: caught error parsing storage configs when refreshing config: %v", err)
			continue
		}
		cache.SetStorageConfigs(cfgs)
		gMappingChecksum = util.SHA1String(mappingData)
		logger.Infof("ConfigReloader: new settings loaded")
	}
}

func periodicReloader(outChan chan bool, intervalSec int) {
	for {
		time.Sleep(time.Second * time.Duration(intervalSec))
		outChan <- true
	}
}

func signalReloader(sigChan chan os.Signal, outChan chan bool) {
	for {
		<-sigChan
		outChan <- true
	}
}

func (m *checkMappingCmd) Run(ctx *cliContext) error {
	if m.MappingFile != "" {
		mappingData, err := ioutil.ReadFile(m.MappingFile)
		if err != nil {
			return fmt.Errorf("error reading config data from file %s: %s", m.MappingFile, err)
		}
		checkMappingData(mappingData)
	} else if m.MappingURL != "" {
		mappingData, err := readMapping(m.MappingURL, "")
		if err != nil {
			return fmt.Errorf("error reading config data from URL %s: %s", m.MappingURL, err)
		}
		checkMappingData(mappingData)
	} else {
		return errors.New("must specify either --url or --file")
	}
	return nil
}

func (q *checkQueryCmd) Run(ctx *cliContext) error {
	logger := createLogger(true)

	if q.MappingFile != "" && q.MappingURL != "" {
		return errors.New("must specify either --url or --file")
	}

	mappingData, err := readMapping(q.MappingURL, q.MappingFile)
	if err != nil {
		return fmt.Errorf("error reading config data: %s", err)
	}

	rules, err := proxy.ParseRules(mappingData, logger)
	if err != nil {
		return fmt.Errorf("error parsing mapping rules: %s", err)
	}

	matches, err := rules.Match(q.Query, q.Method)
	if err != nil {
		return fmt.Errorf("error computing the match: %s", err)
	}

	fmt.Fprint(os.Stdout, matches.String())
	return nil
}

func checkMappingData(mapping []byte) {
	logger := createLogger(true)

	rules, err := proxy.ParseRules(mapping, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing mapping rules: %s\n", err)
		os.Exit(1)
	}
	fmt.Println("Rules:")
	rulelist := rules.RuleList()
	width := numberOfDigits(len(rulelist))
	for i, r := range rulelist {
		fmt.Printf("%*d: %s\n", width, i, r.String())
	}
}

func numberOfDigits(n int) int {
	nod := 0
	for n != 0 {
		n /= 10
		nod++
	}
	return nod
}

func createLogger(debug bool) *apexlog.Logger {
	if debug {
		return &apexlog.Logger{
			Handler: apexlogtext.New(os.Stderr),
			Level:   apexlog.DebugLevel,
		}
	}
	return &apexlog.Logger{
		Handler: apexlogjson.New(os.Stderr),
		Level:   apexlog.InfoLevel,
	}
}

func readMapping(url string, path string) ([]byte, error) {
	if url != "" {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("couldn't read mapping rules from URL %q: %s", url, resp.Status)
		}
		return ioutil.ReadAll(resp.Body)
	} else if path != "" {
		return ioutil.ReadFile(path)
	}
	return nil, errors.New("no URL or path to mapping file")
}
