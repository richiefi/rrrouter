package testhelp

import (
	"fmt"
	"sort"
	"testing"

	"encoding/json"

	apexlog "github.com/apex/log"
	apextext "github.com/apex/log/handlers/text"
)

// ApexLogBridge is a test logging helper
type ApexLogBridge struct {
	test *testing.T
}

// NewLogger creates a new test logger
func NewLogger(t *testing.T) *apexlog.Logger {
	logger := &apexlog.Logger{
		Handler: NewApexLogBridge(t),
		Level:   apexlog.DebugLevel,
	}
	return logger
}

// NewApexLogBridge creates a new apex log bridge
func NewApexLogBridge(test *testing.T) *ApexLogBridge {
	return &ApexLogBridge{test: test}
}

// field used for sorting.
type field struct {
	Name  string
	Value interface{}
}

// by sorts projects by call count.
type byName []field

func (a byName) Len() int           { return len(a) }
func (a byName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byName) Less(i, j int) bool { return a[i].Name < a[j].Name }

// HandleLog .. .. handles a log
func (h *ApexLogBridge) HandleLog(e *apexlog.Entry) error {
	level := apextext.Strings[e.Level]

	var fields []field

	for k, v := range e.Fields {
		fields = append(fields, field{k, v})
	}

	sort.Sort(byName(fields))

	msg := fmt.Sprintf("%6s %s", level, e.Message)

	for _, f := range fields {
		msg = fmt.Sprintf("%s %s=%v", msg, f.Name, f.Value)
	}

	// marshal to json just to make sure it doesn't cause errors
	_, err := json.Marshal(e)
	if err != nil {
		panic(err)
	}

	h.test.Log(msg)
	return nil
}
