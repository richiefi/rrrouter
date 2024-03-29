package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	apexlog "github.com/apex/log"
	"github.com/richiefi/rrrouter/yamlconfig"
)

type ruleType int

const (
	ruleTypeProxy ruleType = 1
	ruleTypeCopy  ruleType = 2
)

var (
	knownMethodsMap = map[string]bool{
		"HEAD":    true,
		"OPTIONS": true,
		"GET":     true,
		"POST":    true,
		"DELETE":  true,
		"PUT":     true,
		"TRACE":   true,
	}

	knownTypesMap = map[string]ruleType{
		"proxy":        ruleTypeProxy,
		"copy_traffic": ruleTypeCopy,
	}
)

// RuleSource is a source of rules, e.g. a JSON file
type RuleSource struct {
	Enabled           *bool                  `json:"enabled"`
	Methods           []string               `json:"methods"`
	Scheme            string                 `json:"scheme"`
	Host              string                 `json:"host"`
	Path              string                 `json:"path"`
	Destination       string                 `json:"destination"`
	Internal          bool                   `json:"internal"`
	Type              *string                `json:"type"`
	HostHeader        string                 `json:"hostheader"`
	Recompression     bool                   `json:"recompression"`
	CacheId           string                 `json:"cache"`
	ForceRevalidate   int                    `json:"force_revalidate"`
	RequestHeaders    map[string]interface{} `json:"request_headers"`
	ResponseHeaders   map[string]string      `json:"response_headers"`
	RestartOnRedirect bool                   `json:"restart_on_redirect"`
	RetryRule         *RuleSource            `json:"retry_rule"`
}

type rulesConfig struct {
	RuleSources []RuleSource `json:"rules"`
}

// Rules is a list of rules... and a logger?
type Rules struct {
	rules  []*Rule
	logger *apexlog.Logger
}

// NewRules builds a new rules list
func NewRules(ruleSources []RuleSource, logger *apexlog.Logger) (*Rules, error) {
	rules := make([]*Rule, 0, len(ruleSources))
	for _, rsrc := range ruleSources {
		enabled := true
		if rsrc.Enabled != nil {
			enabled = *rsrc.Enabled
		}

		if rsrc.Path == "" || rsrc.Destination == "" {
			return nil, fmt.Errorf("rule had empty path %q or destination %q", rsrc.Path, rsrc.Destination)
		}
		methodMap, badmeths := checkMethods(rsrc.Methods)
		if len(badmeths) > 0 {
			return nil, fmt.Errorf("rule had bad methods %q in method list %q", badmeths, rsrc.Methods)
		}
		var ruleType ruleType
		if rsrc.Type == nil {
			ruleType = ruleTypeProxy
		} else {
			var ok bool
			ruleType, ok = knownTypesMap[*rsrc.Type]
			if !ok {
				return nil, fmt.Errorf("unrecognized rule type %q", ruleType)
			}
		}
		hostHeader := HostHeader{Behavior: HostHeaderDefault}
		switch rsrc.HostHeader {
		case "":
			hostHeader = HostHeader{Behavior: HostHeaderDefault}
		case "original":
			hostHeader = HostHeader{Behavior: HostHeaderOriginal}
		case "destination":
			hostHeader = HostHeader{Behavior: HostHeaderDestination}
		default:
			hostHeader = HostHeader{Behavior: HostHeaderOverride, Override: rsrc.HostHeader}
		}
		recompression := false
		if rsrc.Recompression {
			recompression = true
		}
		cacheId := ""
		if len(rsrc.CacheId) > 0 {
			cacheId = rsrc.CacheId
		}
		forceRevalidate := 0
		if rsrc.ForceRevalidate > 0 {
			forceRevalidate = rsrc.ForceRevalidate
		}
		requestHeaders := make(map[string]*string, 0)
		if len(rsrc.RequestHeaders) > 0 {
			for k, v := range rsrc.RequestHeaders {
				if v == nil {
					requestHeaders[strings.ToLower(strings.TrimSpace(k))] = nil
				} else if val, ok := v.(string); ok {
					requestHeaders[strings.ToLower(strings.TrimSpace(k))] = &val
				}
			}
		}
		responseHeaders := make(map[string]string, 0)
		if len(rsrc.ResponseHeaders) > 0 {
			for k, v := range rsrc.ResponseHeaders {
				responseHeaders[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		restartOnRedirect := false
		if rsrc.RestartOnRedirect {
			restartOnRedirect = true
		}
		var retryRule *Rule
		if rsrc.RetryRule != nil {
			rRules, err := NewRules([]RuleSource{(*rsrc.RetryRule)}, logger)
			if err != nil {
				return nil, err
			}
			if len(rRules.rules) > 0 {
				retryRule = rRules.rules[0]
			}
		}
		rule, err := NewRule(enabled, rsrc.Scheme, rsrc.Host, rsrc.Path, rsrc.Destination, rsrc.Internal, methodMap, ruleType, hostHeader, recompression, cacheId, forceRevalidate, requestHeaders, responseHeaders, restartOnRedirect, retryRule)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return &Rules{
		rules:  rules,
		logger: logger,
	}, nil
}

func checkMethods(methods []string) (map[string]bool, []string) {
	badmeths := make([]string, 0, len(methods))
	methodMap := make(map[string]bool, len(methods))
	for _, m := range methods {
		if _, ok := knownMethodsMap[m]; !ok {
			badmeths = append(badmeths, m)
		} else {
			methodMap[m] = true
		}
	}
	return methodMap, badmeths
}

// ParseRules parses a YAML or JSON byte slice into a list of rules
func ParseRules(rcfg []byte, logger *apexlog.Logger) (*Rules, error) {
	var rc rulesConfig
	jsonbytes, err := yamlconfig.Convert(rcfg)
	if err != nil {
		err = json.Unmarshal(rcfg, &rc)
	} else {
		err = json.Unmarshal(jsonbytes, &rc)
	}
	if err != nil {
		return nil, fmt.Errorf("error parsing rules configuration: %s", err)
	}
	if len(rc.RuleSources) == 0 {
		return nil, errors.New("error parsing rules configuration: at least one rule is required")
	}
	return NewRules(rc.RuleSources, logger)
}

func (rs *Rules) String() string {
	return fmt.Sprintf("Rules: %v", rs.rules)
}

// RuleList makes a rule list from the Rules rule list
func (rs *Rules) RuleList() []Rule {
	rl := make([]Rule, 0, len(rs.rules))
	for _, r := range rs.rules {
		rl = append(rl, *r)
	}
	return rl
}

type ruleMatch struct {
	rule   *Rule
	target string
}

func (rm *ruleMatch) String() string {
	return fmt.Sprintf("%v\n(Computed target: %s)\n", rm.rule, rm.target)
}

// RuleMatchResults represents a possible matching rule
type RuleMatchResults struct {
	proxyMatch *ruleMatch
	copyMatch  *ruleMatch
}

func (res *RuleMatchResults) String() string {
	var tokens []string

	tokens = append(tokens, "Proxy:")

	if res.proxyMatch != nil {
		tokens = append(tokens, res.proxyMatch.String())
	} else {
		tokens = append(tokens, "none")
	}

	tokens = append(tokens, "\n")

	tokens = append(tokens, "Copy:")

	if res.copyMatch != nil {
		tokens = append(tokens, res.copyMatch.String())
	} else {
		tokens = append(tokens, "none")
	}

	tokens = append(tokens, "\n")

	return strings.Join(tokens, " ")
}

// Match matches the path and method against the Rules list and returns RuleMatchResults
func (rs *Rules) Match(s, method string) (*RuleMatchResults, error) {
	var proxyMatch *ruleMatch
	var copyMatch *ruleMatch

	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	uri := u.RequestURI()
RulesLoop:
	for _, r := range rs.rules {
		if r.enabled == false {
			continue
		}
		if len(r.methods) > 0 && !r.methods[method] {
			continue
		}
		result, err := r.attemptMatch(u.Scheme, u.Host, uri)
		if err != nil {
			return nil, err
		}
		if result != nil {
			rm := &ruleMatch{
				rule:   r,
				target: *result,
			}
			switch r.ruleType {
			case ruleTypeProxy:
				proxyMatch = rm
				break RulesLoop
			case ruleTypeCopy:
				if copyMatch == nil {
					copyMatch = rm
				}
			}
		}
	}
	return &RuleMatchResults{
		proxyMatch: proxyMatch,
		copyMatch:  copyMatch,
	}, nil
}
