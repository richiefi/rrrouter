package proxy

import (
	"net/http"
	"testing"

	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"

	"github.com/richiefi/rrrouter/usererror"
)

func TestRemoveInternalHeader_all_removed(t *testing.T) {
	header := http.Header{}
	header.Set("Accept", "*/*")
	header.Set(headerRichieOriginatingIP, "192.168.0.1")
	header.Set(headerRichieRequestID, "ASDF-BLART")
	header.Set(headerRichieRoutingSecret, "SECRETS!")

	expect := http.Header{
		"Accept": []string{"*/*"},
	}
	err := ensureInternalHeaders(
		header,
		false,
		[]string{"SECRETS!"},
		func() string { return "w" },
	)
	require.Nil(t, err)
	require.Equal(t, header, expect)
}

func TestRemoveInternalHeader_accept_old_secret(t *testing.T) {
	header := http.Header{}
	header.Set("Accept", "*/*")
	header.Set(headerRichieOriginatingIP, "192.168.0.1")
	header.Set(headerRichieRequestID, "ASDF-BLART")
	header.Set(headerRichieRoutingSecret, "SECRETS!")

	expect := http.Header{
		"Accept": []string{"*/*"},
	}
	err := ensureInternalHeaders(
		header,
		false,
		[]string{"TOTALLY_LATEST_SECRETS", "NEWER_SECRETS", "SECRETS!"},
		func() string { return "w" },
	)
	require.Nil(t, err)
	require.Equal(t, header, expect)
}

func TestRemoveInternalHeader_no_error_if_some_missing(t *testing.T) {
	header := http.Header{}
	header.Set("Accept", "*/*")
	header.Set(headerRichieOriginatingIP, "192.168.0.1")
	header.Set(headerRichieRequestID, "ASDF-BLART")

	expect := http.Header{
		"Accept": []string{"*/*"},
	}
	err := ensureInternalHeaders(
		header,
		false,
		[]string{"SECRETS!"},
		func() string { return "w" },
	)
	require.Nil(t, err)
	require.Equal(t, header, expect)
}

func TestRemoveInternalHeader_error_if_bad_secret(t *testing.T) {
	header := http.Header{}
	header.Set("Accept", "*/*")
	header.Set(headerRichieOriginatingIP, "192.168.0.1")
	header.Set(headerRichieRequestID, "ASDF-BLART")
	header.Set(headerRichieRoutingSecret, "SECRETS!")

	err := ensureInternalHeaders(
		header,
		false,
		[]string{"q"},
		func() string { return "w" },
	)
	require.NotNil(t, err, "No error")
	uerr, ok := err.(*usererror.UserError)
	require.True(t, ok, "not usererror.UserError", err)
	require.Equal(t, uerr.Code, http.StatusProxyAuthRequired)
}

func TestAddInternalHeader_all_appear_if_nothing_there(t *testing.T) {
	header := http.Header{}
	header.Set("Accept", "*/*")

	err := ensureInternalHeaders(
		header,
		true,
		[]string{"q"},
		func() string { return "192.168.2.1" },
	)
	require.Nil(t, err)
	require.Equal(t, header.Get(headerRichieOriginatingIP), "192.168.2.1")
	require.Equal(t, header.Get(headerRichieRoutingSecret), "q")
	_, err = uuid.FromString(header.Get(headerRichieRequestID))
	require.Nil(t, err, "Error decoding request id")
}

func TestAddInternalHeader_add_missing_request_id(t *testing.T) {
	header := http.Header{}
	header.Set("Accept", "*/*")
	header.Set(headerRichieRoutingSecret, "SECRETS!")
	header.Set(headerRichieOriginatingIP, "192.168.0.1")

	err := ensureInternalHeaders(
		header,
		true,
		[]string{"SECRETS!"},
		func() string { return "192.168.2.1" },
	)
	require.Nil(t, err)
	require.Equal(t, header.Get(headerRichieOriginatingIP), "192.168.0.1")
	require.Equal(t, header.Get(headerRichieRoutingSecret), "SECRETS!")
	_, err = uuid.FromString(header.Get(headerRichieRequestID))
	require.Nil(t, err, "Error decoding request id")
}

func TestAddInternalHeader_add_missing_orig_ip(t *testing.T) {
	header := http.Header{}
	header.Set("Accept", "*/*")
	header.Set(headerRichieRoutingSecret, "SECRETS!")
	header.Set(headerRichieRequestID, "6ba7b810-9dad-11d1-80b4-00c04fd430c8")

	err := ensureInternalHeaders(
		header,
		true,
		[]string{"SECRETS!"},
		func() string { return "192.168.2.1" },
	)
	require.Nil(t, err)
	require.Equal(t, header.Get(headerRichieOriginatingIP), "192.168.2.1")
	require.Equal(t, header.Get(headerRichieRoutingSecret), "SECRETS!")
	require.Equal(t, header.Get(headerRichieRequestID), "6ba7b810-9dad-11d1-80b4-00c04fd430c8")
}

func TestAddInternalHeader_error_if_bad_secret(t *testing.T) {
	header := http.Header{}
	header.Set("Accept", "*/*")
	header.Set(headerRichieRoutingSecret, "bad secret")
	header.Set(headerRichieRequestID, "6ba7b810-9dad-11d1-80b4-00c04fd430c8")

	err := ensureInternalHeaders(
		header,
		true,
		[]string{"SECRETS!"},
		func() string { return "192.168.2.1" },
	)
	require.NotNil(t, err, "No error")
	uerr, ok := err.(*usererror.UserError)
	require.True(t, ok, "not usererror.UserError", err)
	require.Equal(t, uerr.Code, http.StatusProxyAuthRequired)
}

func TestAddInternalHeader_error_if_custom_headers_without_secret(t *testing.T) {
	header := http.Header{}
	header.Set("Accept", "*/*")
	header.Set(headerRichieRequestID, "6ba7b810-9dad-11d1-80b4-00c04fd430c8")

	err := ensureInternalHeaders(
		header,
		true,
		[]string{"SECRETS!"},
		func() string { return "192.168.2.1" },
	)
	require.NotNil(t, err, "No error")
	uerr, ok := err.(*usererror.UserError)
	require.True(t, ok, "not usererror.UserError", err)
	require.Equal(t, uerr.Code, http.StatusProxyAuthRequired)
}
