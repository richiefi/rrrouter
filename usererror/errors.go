package usererror

import (
	"fmt"
	"sort"
	"strings"
)

// ErrorBuilder builds an error from the fields in a string map
type ErrorBuilder struct {
	fields map[string]interface{}
}

// Fields is a string map holding information about an error
type Fields map[string]interface{}

// BuildError builds an error from the fields in a string map
func BuildError(fields Fields) *ErrorBuilder {
	return &ErrorBuilder{
		fields: fields,
	}
}

// CreateError builds an error from a HTTP-style error code and a message string
func CreateError(code int, message string) JSONableError {
	return &UserError{
		Code:    code,
		Message: message,
	}
}

// CreateError builds an error from a HTTP-style error code, a message string, and the fields map
func (eb *ErrorBuilder) CreateError(code int, message string) JSONableError {
	return &UserError{
		Code:    code,
		Message: message,
		Fields:  eb.fields,
	}
}

// field used for sorting.
type field struct {
	Name  string
	Value interface{}
}

type byName []field

func (a byName) Len() int           { return len(a) }
func (a byName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byName) Less(i, j int) bool { return a[i].Name < a[j].Name }

// JSONableError is a JSON-compatible error
type JSONableError interface {
	error
	JSON() map[string]interface{}
}

// UserError is an error we present to an end user
type UserError struct {
	Code    int
	Message string
	Fields  map[string]interface{}
}

// JSON returns the UserError as a JSON-compatible map
func (ue *UserError) JSON() map[string]interface{} {
	m := map[string]interface{}{
		"Message": ue.Message,
	}
	if ue.Fields != nil {
		m["Fields"] = ue.Fields
	}
	return m
}

func (ue *UserError) Error() string {
	baseString := fmt.Sprintf("UserError: Code: %d, Message: %s", ue.Code, ue.Message)
	if ue.Fields == nil {
		return baseString
	}

	var fields []field

	for k, v := range ue.Fields {
		fields = append(fields, field{k, v})
	}
	sort.Sort(byName(fields))

	fieldStrings := make([]string, 0, len(fields))
	for _, f := range fields {
		fieldStrings = append(fieldStrings, fmt.Sprintf("%s=%+v", f.Name, f.Value))
	}
	return fmt.Sprintf("%s Fields: %s", baseString, strings.Join(fieldStrings, " "))
}
