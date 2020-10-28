package proxy

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Rule describes a single forwarding rule
type Rule struct {
	pattern        string
	re             *regexp.Regexp
	dest           string
	internal       bool
	methods        map[string]bool
	ruleType       ruleType
	addCompression bool
}

// NewRule builds a new Rule
func NewRule(pattern, destination string, internal bool, methods map[string]bool, ruleType ruleType, addCompression bool) (*Rule, error) {
	lowpat := strings.ToLower(pattern)
	addAnyProto := !(strings.HasPrefix(lowpat, "http://") || strings.HasPrefix(lowpat, "https://"))
	inputParts := strings.Split(pattern, "*")
	finalParts := make([]string, 0, len(inputParts)*3)
	finalParts = append(finalParts, `(?i)\A`)
	wildcardCount := 0
	if addAnyProto {
		finalParts = append(finalParts, "https?://")
	}
	for i, p := range inputParts {
		qp := regexp.QuoteMeta(p)
		finalParts = append(finalParts, qp)

		if i < len(inputParts)-1 {
			finalParts = append(finalParts, "(.*)")
			wildcardCount++
		}
	}
	finalParts = append(finalParts, `\z`)

	repattern := strings.Join(finalParts, "")
	r := regexp.MustCompile(repattern)
	rule := &Rule{
		pattern:  pattern,
		re:       r,
		dest:     destination,
		internal: internal,
		methods:  methods,
		ruleType: ruleType,
		addCompression: addCompression,
	}

	// First parse the main destination
	ctx := &destinationParseContext{
		destination:         rule.dest,
		input:               destination,
		replacePlaceholders: false,
		maxPlaceholder:      -1,
	}
	_, err := parseDestinationWithContext(ctx)
	if err != nil {
		return nil, err
	}
	if ctx.maxPlaceholder > wildcardCount {
		return nil, fmt.Errorf("destination used placeholder %d but there are only %d wildcards in the pattern", ctx.maxPlaceholder, wildcardCount)
	}

	// And if there's a copy target, check that too
	// if copyDest != "" {
	// 	ctx := &destinationParseContext{
	// 		destination:         rule.copyDest,
	// 		input:               copyDest,
	// 		replacePlaceholders: false,
	// 		maxPlaceholder:      -1,
	// 	}

	// 	_, err = parseDestinationWithContext(ctx)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	if ctx.maxPlaceholder > wildcardCount {
	// 		return nil, fmt.Errorf("Copy destination used placeholder %d but there are only %d wildcards in the pattern", ctx.maxPlaceholder, wildcardCount)
	// 	}
	// }

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

func (r *Rule) attemptMatch(s string) (*string, error) {
	submatches := r.re.FindStringSubmatch(s)
	if submatches == nil {
		return nil, nil
	}

	ctx := &destinationParseContext{
		destination:         r.dest,
		input:               s,
		inputMatches:        submatches,
		replacePlaceholders: true,
	}
	dest, err := parseDestinationWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return &dest, nil
}

func parseDestinationWithContext(ctx *destinationParseContext) (string, error) {
	var buf bytes.Buffer
	nextState := stateLookForNextPlaceholder
	var err error
	for _, destrune := range ctx.destination {
		nextState, err = nextState(&destrune, &buf, ctx)

		if err != nil {
			return "", err
		}
	}
	_, err = nextState(nil, &buf, ctx)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

type destinationParseContext struct {
	destination         string
	input               string
	inputMatches        []string
	maxPlaceholder      int
	replacePlaceholders bool
}

type stateFunc func(r *rune, buf *bytes.Buffer, ctx *destinationParseContext) (stateFunc, error)

func stateLookForNextPlaceholder(r *rune, buf *bytes.Buffer, ctx *destinationParseContext) (stateFunc, error) {
	if r == nil {
		return nil, nil
	}
	switch *r {
	case '$':
		return stateReadPlaceholderNumber, nil
	case '\\':
		return stateReadLiteral, nil
	default:
		buf.WriteRune(*r)
		return stateLookForNextPlaceholder, nil
	}
}

func stateReadPlaceholderNumber(r *rune, buf *bytes.Buffer, ctx *destinationParseContext) (stateFunc, error) {
	var numbuf bytes.Buffer
	var numberAccumulator stateFunc

	finishNumber := func(r *rune, buf *bytes.Buffer, ctx *destinationParseContext) (stateFunc, error) {
		placeholderNum, err := strconv.Atoi(numbuf.String())
		if err != nil {
			return nil, err
		}
		ctx.maxPlaceholder = maxi(ctx.maxPlaceholder, placeholderNum)
		if ctx.replacePlaceholders {
			if placeholderNum >= len(ctx.inputMatches) {
				return nil, fmt.Errorf("destination %q referred to placeholder %d out of bounds. Input %q, matches: %q", ctx.destination, placeholderNum, ctx.input, ctx.inputMatches)
			}
			buf.WriteString(ctx.inputMatches[placeholderNum])
		}
		return stateLookForNextPlaceholder(r, buf, ctx)
	}

	numberAccumulator = func(r *rune, buf *bytes.Buffer, ctx *destinationParseContext) (stateFunc, error) {
		if r == nil {
			return finishNumber(r, buf, ctx)
		}
		switch *r {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			numbuf.WriteRune(*r)
			return numberAccumulator, nil
		default:
			return finishNumber(r, buf, ctx)
		}
	}
	return numberAccumulator(r, buf, ctx)
}

func maxi(i1, i2 int) int {
	if i1 > i2 {
		return i1
	}
	return i2
}

func stateReadLiteral(r *rune, buf *bytes.Buffer, ctx *destinationParseContext) (stateFunc, error) {
	if r == nil {
		return nil, fmt.Errorf("unfinished literal at the end of %q", ctx.destination)
	}
	buf.WriteRune(*r)
	return stateLookForNextPlaceholder, nil
}
