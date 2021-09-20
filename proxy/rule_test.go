package proxy

import (
	"net/url"
	"testing"
)

func TestRule(t *testing.T) {
	type RuleTest struct {
		input       string
		expect      string
		shouldError bool
	}
	tests := []struct {
		scheme      string
		host        string
		pat         string
		dest        string
		shouldError bool
		rtests      []RuleTest
	}{
		{
			scheme: "https",
			host:   "app.example.com",
			pat:    "/config/v1/*",
			dest:   "https://richie-appconfig.herokuapp.com/v1/$1",
			rtests: []RuleTest{
				{
					input:  "https://app.example.com/config/v1/helloworld",
					expect: "https://richie-appconfig.herokuapp.com/v1/helloworld",
				},
				{
					input:  "https://app.example.com/config/v1/paz",
					expect: "https://richie-appconfig.herokuapp.com/v1/paz",
				},
				{
					input:  "http://app.example.com/config/v1/paz",
					expect: "",
				},
			},
		},
		{
			host: "app.example.com",
			pat:  "/config/v1/*",
			dest: "https://richie-appconfig.herokuapp.com/v1/$1",
			rtests: []RuleTest{
				{
					input:  "http://foo",
					expect: "",
				},
				{
					input:  "https://app.example.com/config/v1/helloworld",
					expect: "https://richie-appconfig.herokuapp.com/v1/helloworld",
				},
				{
					input:  "http://app.example.com/config/v1/paz",
					expect: "https://richie-appconfig.herokuapp.com/v1/paz",
				},
			},
		},
		{
			pat:  "/config/v1/*",
			dest: "https://richie-appconfig.herokuapp.com/v1/$1",
			rtests: []RuleTest{
				{
					input:  "http://foo",
					expect: "",
				},
				{
					input:  "https://app.example.com/config/v1/helloworld",
					expect: "https://richie-appconfig.herokuapp.com/v1/helloworld",
				},
				{
					input:  "http://app.example.com/config/v1/paz",
					expect: "https://richie-appconfig.herokuapp.com/v1/paz",
				},
			},
		},
		{
			pat:         "",
			dest:        "",
			shouldError: true,
		},
		{
			pat:         "x",
			dest:        "",
			shouldError: true,
		},
		{
			pat:         "*/*",
			dest:        "https://app.example.com/$1/$2",
			shouldError: true,
		},
		{
			pat:         "*/end",
			dest:        "https://app.example.com/$1",
			shouldError: true,
		},
	}
	for _, test := range tests {
		r, err := NewRule(true, test.scheme, test.host, test.pat, test.dest, false, map[string]bool{}, ruleTypeProxy, HostHeader{Behavior: HostHeaderDefault}, false, "", 0, map[string]string{}, false, nil)
		if err != nil && !test.shouldError {
			t.Errorf("Unexpected error compiling rule from %q, %q: %s", test.pat, test.dest, err)
			continue
		} else if err == nil && test.shouldError {
			t.Errorf("Expected an error compiling rule from %q, %q", test.pat, test.dest)
			continue
		}
		if err != nil {
			continue
		}

		for _, ruletest := range test.rtests {
			u, err := url.Parse(ruletest.input)
			if err != nil && !ruletest.shouldError {
				t.Errorf("Invalid URL: %s", ruletest.input)
			}
			output, err := r.attemptMatch(u.Scheme, u.Host, u.RequestURI())
			if err != nil && !ruletest.shouldError {
				t.Errorf("Matching %q against rule %s caused an error: %s", ruletest.input, r.String(), err)
			} else if err == nil && ruletest.shouldError {
				t.Errorf("Matching %q against rule %s didn't cause an error", ruletest.input, r.String())
			} else if output == nil && ruletest.expect != "" {
				t.Errorf("Matching %q against rule %s returned nil, expected %q", ruletest.input, r.String(), ruletest.expect)
			} else if output != nil && (*output != ruletest.expect) {
				t.Errorf("Matching %q against rule %s returned %q, expected %q", ruletest.input, r.String(), *output, ruletest.expect)
			}
		}
	}
}
