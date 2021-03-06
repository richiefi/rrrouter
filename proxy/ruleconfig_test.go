package proxy

import (
	"testing"

	"github.com/richiefi/rrrouter/testhelp"
	"github.com/stretchr/testify/require"
)

func TestConfigParse_error_cases(t *testing.T) {
	badData := []string{
		``,
		`{`,
		`{"rules": {}}`,
		`{"rules": [{"patttern": "asd", "destination": "zap"}]}`,
		`{"rules": [{"pattern": "asdf, "ddestination": "zap"}]}`,
		`{"rules": [{"pattern": 1, "destination": "zap"}]}`,
		`{"rules": [{"pattern": "asdf", "destination": ["zap"]}]}`,
		`{"rules": [{"pattern": "plop", "destination": "zap$1"}]}`,
	}
	logger := testhelp.NewLogger(t)
	for _, d := range badData {
		_, err := ParseRules([]byte(d), logger)
		require.NotNil(t, err, "Expected parsing as rules to fail", d)
	}
}

func TestConfigParse_success(t *testing.T) {
	src := `{"rules": [
        {
            "pattern": "api.example.com/foo/*",  
            "destination": "http://richie-fooserver.herokuapp.com/v1/$1"
        },
        {
            "pattern": "api.example.com/bar/*", 
            "destination": "http://richie-barserver.herokuapp.com/v1/$1"
        }
        ]
    }`
	rules, err := ParseRules([]byte(src), testhelp.NewLogger(t))
	require.Nil(t, err)
	require.Equal(t, len(rules.rules), 2)

	ruleMatchResults, err := rules.Match("https://api.example.com/foo/zap/fnord", "GET")
	require.Nil(t, err)
	require.NotNil(t, ruleMatchResults)
	require.NotNil(t, ruleMatchResults.proxyMatch)
	require.Equal(t, ruleMatchResults.proxyMatch.target, "http://richie-fooserver.herokuapp.com/v1/zap/fnord")

	ruleMatchResults, err = rules.Match("http://api.example.com/bar/flarp/blart", "GET")
	require.Nil(t, err)
	require.NotNil(t, ruleMatchResults)
	require.NotNil(t, ruleMatchResults.proxyMatch)
	require.Equal(t, ruleMatchResults.proxyMatch.target, "http://richie-barserver.herokuapp.com/v1/flarp/blart")
}

func TestConfigParse_host_headers(t *testing.T) {
	src := `{"rules": [
        {
            "pattern": "api.example.com/foo/*",  
            "destination": "http://localhost:1000/v1/$1",
        },
        {
            "pattern": "api.example.com/bar/*", 
            "destination": "http://localhost:1000/v1/$1",
			"hostheader": "original"
        },
        {
            "pattern": "api.example.com/bar/*", 
            "destination": "http://localhost:1000/v1/$1",
			"hostheader": "example.com:3800"
        },
        {
            "pattern": "api.example.com/bar/*", 
            "destination": "http://localhost:1000/v1/$1",
			"hostheader": "destination"
        }
        ]
    }`
	rules, err := ParseRules([]byte(src), testhelp.NewLogger(t))
	require.Nil(t, err)
	require.Equal(t, 4, len(rules.rules))
	require.Equal(t, HostHeaderDefault, rules.rules[0].hostHeader.Behavior)
	require.Equal(t, HostHeaderOriginal, rules.rules[1].hostHeader.Behavior)
	require.Equal(t, HostHeaderOverride, rules.rules[2].hostHeader.Behavior)
	require.Equal(t, "example.com:3800", rules.rules[2].hostHeader.Override)
	require.Equal(t, HostHeaderDestination, rules.rules[3].hostHeader.Behavior)

}

func TestConfigParse_mismatched_wildcard_count_error(t *testing.T) {
	src := `{"rules": [
        {
            "pattern": "api.example.com/foo/*", 
            "destination": "http://richie-fooserver.herokuapp.com/v1/$1/$2"
        }
        ]
    }`
	_, err := ParseRules([]byte(src), testhelp.NewLogger(t))
	require.NotNil(t, err)
}

func TestConfigParse_copy_traffic_success(t *testing.T) {
	src := `{"rules": [
        {
            "type": "copy_traffic",
            "pattern": "api.example.com/foo/*",
            "destination": "http://richie-copytarget.herokuapp.com/v1/$1",
            "methods": ["HEAD", "OPTIONS"]
        },
        {
            "pattern": "api.example.com/foo/*",
            "destination": "http://richie-fooserver.herokuapp.com/v1/$1"
        }
        ]
    }`
	rules, err := ParseRules([]byte(src), testhelp.NewLogger(t))
	require.Nil(t, err)
	require.Equal(t, len(rules.rules), 2)
	require.Equal(t, rules.rules[0].methods, map[string]bool{"HEAD": true, "OPTIONS": true})
	require.Equal(t, rules.rules[0].dest, "http://richie-copytarget.herokuapp.com/v1/$1")
	require.Equal(t, rules.rules[0].ruleType, ruleTypeCopy)

	require.Equal(t, rules.rules[1].methods, map[string]bool{})
	require.Equal(t, rules.rules[1].dest, "http://richie-fooserver.herokuapp.com/v1/$1")
	require.Equal(t, rules.rules[1].ruleType, ruleTypeProxy)

	ruleMatchResults, err := rules.Match("https://api.example.com/foo/zap/fnord", "HEAD")
	require.Nil(t, err)
	require.NotNil(t, ruleMatchResults)
	require.NotNil(t, ruleMatchResults.copyMatch)
	require.NotNil(t, ruleMatchResults.proxyMatch)
	require.Equal(t, ruleMatchResults.proxyMatch.target, "http://richie-fooserver.herokuapp.com/v1/zap/fnord")
	require.Equal(t, ruleMatchResults.copyMatch.target, "http://richie-copytarget.herokuapp.com/v1/zap/fnord")
}

func TestConfigParse_method_match_required(t *testing.T) {
	src := `{"rules": [
        {
            "type": "copy_traffic",
            "pattern": "api.example.com/foo/*",
            "destination": "http://richie-copytarget.herokuapp.com/v1/$1",
            "methods": ["HEAD", "OPTIONS"]
        },
        {
            "pattern": "api.example.com/foo/*",
            "destination": "http://richie-fooserver.herokuapp.com/v1/$1",
            "methods": ["HEAD", "OPTIONS"]
        }
        ]
    }`
	rules, err := ParseRules([]byte(src), testhelp.NewLogger(t))
	require.Nil(t, err)
	require.Equal(t, len(rules.rules), 2)
	require.Equal(t, rules.rules[0].methods, map[string]bool{"HEAD": true, "OPTIONS": true})
	require.Equal(t, rules.rules[0].dest, "http://richie-copytarget.herokuapp.com/v1/$1")
	require.Equal(t, rules.rules[0].ruleType, ruleTypeCopy)

	require.Equal(t, rules.rules[1].methods, map[string]bool{"HEAD": true, "OPTIONS": true})
	require.Equal(t, rules.rules[1].dest, "http://richie-fooserver.herokuapp.com/v1/$1")
	require.Equal(t, rules.rules[1].ruleType, ruleTypeProxy)

	ruleMatchResults, err := rules.Match("https://api.example.com/foo/zap/fnord", "GET")
	require.Nil(t, err)
	require.NotNil(t, ruleMatchResults)
	require.True(t, ruleMatchResults.copyMatch == nil)
	require.True(t, ruleMatchResults.proxyMatch == nil)
}

func TestConfigParse_copy_not_found_if_proxy_rule_found_first(t *testing.T) {
	src := `{"rules": [
        {
            "pattern": "api.example.com/foo/*",
            "destination": "http://richie-fooserver.herokuapp.com/v1/$1"
        },
        {
            "type": "copy_traffic",
            "pattern": "api.example.com/foo/*",
            "destination": "http://richie-copytarget.herokuapp.com/v1/$1",
            "methods": ["HEAD", "OPTIONS"]
        }
        ]
    }`
	rules, err := ParseRules([]byte(src), testhelp.NewLogger(t))
	require.Nil(t, err)
	require.Equal(t, len(rules.rules), 2)
	require.Equal(t, rules.rules[0].dest, "http://richie-fooserver.herokuapp.com/v1/$1")
	require.Equal(t, rules.rules[0].ruleType, ruleTypeProxy)

	require.Equal(t, rules.rules[1].dest, "http://richie-copytarget.herokuapp.com/v1/$1")
	require.Equal(t, rules.rules[1].ruleType, ruleTypeCopy)

	ruleMatchResults, err := rules.Match("https://api.example.com/foo/zap/fnord", "HEAD")
	require.Nil(t, err)
	require.NotNil(t, ruleMatchResults)
	// require.Nil is giving me expected nil value but got: (*proxy.ruleMatch)(<nil>)
	require.True(t, ruleMatchResults.copyMatch == nil)
	require.NotNil(t, ruleMatchResults.proxyMatch)
	require.Equal(t, ruleMatchResults.proxyMatch.target, "http://richie-fooserver.herokuapp.com/v1/zap/fnord")
}

func TestConfigParse_copy_method_check(t *testing.T) {
	src := `{"rules": [
        {
            "pattern": "api.example.com/foo/*",
            "destination": "http://richie-fooserver.herokuapp.com/v1/$1",
            "methods": ["HEAD ", "get", "DELETE", "trace", "POST", "foo", "OPTIONS", "GET", "PUT", "TRACE"]
        }
        ]
    }`
	_, err := ParseRules([]byte(src), testhelp.NewLogger(t))
	require.NotNil(t, err)
	require.Equal(t, err.Error(), `rule had bad methods ["HEAD " "get" "trace" "foo"] in method list ["HEAD " "get" "DELETE" "trace" "POST" "foo" "OPTIONS" "GET" "PUT" "TRACE"]`)
}

func TestConfigParse_rule_match_has_a_string_representation(t *testing.T) {
	src := `{"rules": [
        {
            "pattern": "api.example.com/foo/*",
            "destination": "http://richie-fooserver.herokuapp.com/v1/$1"
        },
        {
            "type": "copy_traffic",
            "pattern": "api.example.com/foo/*",
            "destination": "http://richie-copytarget.herokuapp.com/v1/$1",
            "methods": ["HEAD", "OPTIONS"]
        }
        ]
    }`
	rules, err := ParseRules([]byte(src), testhelp.NewLogger(t))
	require.Nil(t, err)

	ruleMatchResults, err := rules.Match("https://api.example.com/foo/zap/fnord", "HEAD")
	require.Nil(t, err)
	require.NotNil(t, ruleMatchResults)

	require.True(t, len(ruleMatchResults.String()) > 0)
}

func TestConfigParse_rule_order_is_preserved_and_first_match_used(t *testing.T) {
	src := `{"rules": [
        {
            "pattern": "api.example.com/foo/*",
            "destination": "http://example.com/v1/$1"
        },
        {
            "pattern": "api.example.com/foo/*",
            "destination": "http://richie-fooserver.herokuapp.com/v1/$1"
        },
        ]
    }`
	rules, err := ParseRules([]byte(src), testhelp.NewLogger(t))
	require.Nil(t, err)

	ruleMatchResults, err := rules.Match("https://api.example.com/foo/zap/fnord", "HEAD")
	require.Nil(t, err)
	require.NotNil(t, ruleMatchResults)

	require.Equal(t, "http://example.com/v1/zap/fnord", ruleMatchResults.proxyMatch.target)
}

func TestConfigParse_rule_can_be_disabled(t *testing.T) {
	src := `{"rules": [
        {
            "pattern": "api.example.com/foo/*",
            "destination": "http://example.com/v1/$1",
			"enabled": false
        },
        {
            "pattern": "api.example.com/foo/*",
            "destination": "http://richie-fooserver.herokuapp.com/v1/$1"
        },
        {
            "pattern": "api.example.com/foo2/*",
            "destination": "http://richie-fooserver.herokuapp.com/v2/$1",
            "enabled": true
        },
        ]
    }`
	rules, err := ParseRules([]byte(src), testhelp.NewLogger(t))
	require.Nil(t, err)
	require.Equal(t, len(rules.rules), 3)

	ruleMatchResults, err := rules.Match("https://api.example.com/foo/zap/fnord", "GET")
	require.Nil(t, err)
	require.NotNil(t, ruleMatchResults)
	require.Equal(t, "http://richie-fooserver.herokuapp.com/v1/zap/fnord", ruleMatchResults.proxyMatch.target)

	ruleMatchResults, err = rules.Match("https://api.example.com/foo2/zap/fnord", "GET")
	require.Nil(t, err)
	require.NotNil(t, ruleMatchResults)
	require.Equal(t, "http://richie-fooserver.herokuapp.com/v2/zap/fnord", ruleMatchResults.proxyMatch.target)
}
