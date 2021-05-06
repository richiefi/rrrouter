package proxy

import (
	"testing"
)

func TestRule(t *testing.T) {
	type RuleTest struct {
		input       string
		expect      string
		shouldError bool
	}
	tests := []struct {
		pat         string
		re          string
		dest        string
		shouldError bool
		rtests      []RuleTest
	}{
		{
			pat:  "app.example.com/config/v1/*",
			re:   `(?i)\Ahttps?://app\.example\.com/config/v1/(.*)\z`,
			dest: "https://richie-appconfig.herokuapp.com/v1/$1",
			rtests: []RuleTest{
				{
					input:  "foo",
					expect: "",
				},
				{
					input:  "http://app.example.com/config/v1/helloworld",
					expect: "https://richie-appconfig.herokuapp.com/v1/helloworld",
				},
				{
					input:  "https://app.example.com/config/v1/paz",
					expect: "https://richie-appconfig.herokuapp.com/v1/paz",
				},
			},
		},
		{
			pat:  "https://*-dist.example.com/whoami/*",
			re:   `(?i)\Ahttps://(.*)-dist\.example\.com/whoami/(.*)\z`,
			dest: "https://richie-appconfig.herokuapp.com/v1/$2",
			rtests: []RuleTest{
				{
					input:  "https://cust-dist.example.com/whoami/foo",
					expect: "https://richie-appconfig.herokuapp.com/v1/foo",
				},
				{
					input:  "http://cust-dist.example.com/whoami/foo",
					expect: "",
				},
			},
		},
		{
			pat:  "https://app.example.com/file-dist/*",
			re:   `(?i)\Ahttps://app\.example\.com/file-dist/(.*)\z`,
			dest: "https://filestore.example.com/file-dist/file-dist/$1",
			rtests: []RuleTest{
				{
					input:  "https://app.example.com/file-dist/frank/zappa",
					expect: "https://filestore.example.com/file-dist/file-dist/frank/zappa",
				},
			},
		},
		{
			pat:  "https://api.example.com/v1/*",
			re:   `(?i)\Ahttps://api\.example\.com/v1/(.*)\z`,
			dest: "https://exampleapp-api.herokuapp.com/$1",
			rtests: []RuleTest{
				{
					input:  "https://api.example.com/v1/q",
					expect: "https://exampleapp-api.herokuapp.com/q",
				},
			},
		},
		{
			pat:         "https://api.example.com/v1/*",
			re:          `(?i)\Ahttps://api\.example\.com/v1/(.*)\z`,
			dest:        "https://exampleapp-api.herokuapp.com/$1/$2",
			shouldError: true,
		},
		{
			pat:         "https://api.example.com/v1/*",
			re:          `(?i)\Ahttps://api\.example\.com/v1/(.*)\z`,
			dest:        "https://exampleapp-api.herokuapp.com/$1/\\$2",
			shouldError: false,
			rtests: []RuleTest{
				{
					input:  "https://api.example.com/v1/q",
					expect: "https://exampleapp-api.herokuapp.com/q/$2",
				},
			},
		},
		{
			pat:         "https://app.example.com/*/exampleapp/*.exampleapp.js",
			re:          `(?i)\Ahttps://app\.example\.com/(.*)/exampleapp/(.*)\.exampleapp\.js\z`,
			dest:        "https://richie-exampleapp.herokuapp.com/$1/exampleapp/$2.exampleapp.js",
			shouldError: false,
			rtests: []RuleTest{
				{
					input:  "https://app.example.com/ios/exampleapp/100.exampleapp.js",
					expect: "https://richie-exampleapp.herokuapp.com/ios/exampleapp/100.exampleapp.js",
				},
				{
					input:  "https://app.example.com/android/exampleapp/1.0.0.0.exampleapp.js",
					expect: "https://richie-exampleapp.herokuapp.com/android/exampleapp/1.0.0.0.exampleapp.js",
				},
			},
		},
		{
			pat:         "*://app.example.com/*/exampleapp/*.exampleapp.js",
			re:          `(?i)\A(.*)://app\.example\.com/(.*)/exampleapp/(.*)\.exampleapp\.js\z`,
			dest:        "$1://richie-exampleapp.herokuapp.com/$2/exampleapp/$3.exampleapp.js",
			shouldError: false,
			rtests: []RuleTest{
				{
					input:  "http://app.example.com/ios/exampleapp/100.exampleapp.js",
					expect: "http://richie-exampleapp.herokuapp.com/ios/exampleapp/100.exampleapp.js",
				},
				{
					input:  "https://app.example.com/ios/exampleapp/100.exampleapp.js",
					expect: "https://richie-exampleapp.herokuapp.com/ios/exampleapp/100.exampleapp.js",
				},
			},
		},
	}
	for _, test := range tests {
		r, err := NewRule(true, test.pat, test.dest, false, map[string]bool{}, ruleTypeProxy, HostHeader{Behavior: HostHeaderDefault}, false, "", 0, map[string]string{}, false, nil)
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

		if r.re.String() != test.re {
			t.Errorf("Rule %q resulted in regexp %q, expected %q", test.pat, r.re.String(), test.re)
		}
		for _, ruletest := range test.rtests {
			output, err := r.attemptMatch(ruletest.input)
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
