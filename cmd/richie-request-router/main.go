package main

import (
	"errors"
	"fmt"
	"github.com/richiefi/rrrouter/caching"
	"io/ioutil"
	"net/http"
	"os"
	"time"

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
	err := ctx.Run(&cliContext{Debug: cli.Debug})
	ctx.FatalIfErrorf(err)
}

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
	server.Run(&c, router, logger, ca)
	return nil
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
