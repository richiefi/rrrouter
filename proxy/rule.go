package proxy

import (
	"errors"
	"fmt"
	"strings"
)

// Rule describes a single forwarding rule
type Rule struct {
	enabled          bool
	scheme           string
	host             string
	pattern          string
	wci              []int
	dest             string
	internal         bool
	methods          map[string]bool
	ruleType         ruleType
	recompression    bool
	hostHeader       HostHeader
	cacheId          string
	forceRevalidate  int
	responseHeaders  map[string]string
	flattenRedirects bool
	retryRule        *Rule
}

type HostHeader struct {
	Behavior HostHeaderBehavior
	Override string
}

type HostHeaderBehavior int

const (
	HostHeaderDefault HostHeaderBehavior = iota
	HostHeaderOriginal
	HostHeaderOverride
	HostHeaderDestination
)

// NewRule builds a new Rule
func NewRule(enabled bool, scheme, host, pattern, destination string, internal bool, methods map[string]bool, ruleType ruleType, hostHeader HostHeader,
	recompression bool, cacheId string, forceRevalidate int, responseHeaders map[string]string, flattenRedirects bool, retryRule *Rule) (*Rule, error) {
	if len(pattern) == 0 {
		return nil, errors.New("Empty pattern")
	}
	if len(destination) == 0 {
		return nil, errors.New("Empty destination")
	}
	lowpat := strings.ToLower(pattern)
	firstIdx := strings.Index(lowpat, "*")
	wci := make([]int, 0)
	if firstIdx != -1 {
		lastIdx := strings.LastIndex(lowpat, "*")
		if firstIdx != lastIdx {
			return nil, errors.New("Wildcard count in pattern > 1")
		} else if firstIdx != len(lowpat)-1 {
			return nil, errors.New("Wildcard must be placed as last character in the pattern")
		}
		wci = append(wci, firstIdx)
	}

	rule := &Rule{
		enabled:          enabled,
		scheme:           scheme,
		host:             host,
		pattern:          pattern,
		wci:              wci,
		dest:             destination,
		internal:         internal,
		methods:          methods,
		ruleType:         ruleType,
		hostHeader:       hostHeader,
		recompression:    recompression,
		cacheId:          cacheId,
		forceRevalidate:  forceRevalidate,
		responseHeaders:  responseHeaders,
		flattenRedirects: flattenRedirects,
		retryRule:        retryRule,
	}

	return rule, nil
}

func (r *Rule) String() string {
	intext := "E"
	if r.internal {
		intext = "I"
	}
	rtype := "P"
	if r.ruleType == ruleTypeCopy {
		rtype = "C"
	}
	methods := "*"
	if len(r.methods) > 0 {
		mlist := make([]string, 0, len(r.methods))
		for method := range r.methods {
			mlist = append(mlist, method)
		}
		methods = strings.Join(mlist, ",")
	}
	return fmt.Sprintf("Rule (%s,%s) %s %q -> %q", intext, rtype, methods, r.pattern, r.dest)
}

func (r *Rule) attemptMatch(scheme, host, uri string) (*string, error) {
	if (len(r.scheme) > 0 && r.scheme != scheme) || (len(r.host) > 0 && r.host != host) {
		return nil, nil
	}

	if len(r.wci) == 1 {
		pathLen := len(uri)
		wcIdx := r.wci[0]
		if pathLen-1 < wcIdx {
			return nil, nil
		}

		idx := strings.Index(uri, r.pattern[:wcIdx])
		if idx != 0 {
			return nil, nil
		}

		captured := uri[wcIdx:]
		d := strings.Replace(r.dest, "$1", captured, 1)
		return &d, nil
	} else if len(r.wci) == 0 {
		if r.pattern == uri {
			return &r.dest, nil
		}
		return nil, nil
	} else {
		return nil, errors.New("Wildcard count in pattern > 1")
	}
}
