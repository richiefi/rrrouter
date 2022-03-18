package util

import (
	"net/http"
	"net/url"
	"os"
	"strings"
)

var etagToken *string

func CurrentEtagToken() *string {
	if etagToken == nil {
		token := os.Getenv("ETAG_TOKEN")
		if len(token) > 0 {
			etagToken = &token
		}
	}

	return etagToken
}

func AddETagSuffix(etag string) string {
	if token := CurrentEtagToken(); token != nil {
		if strings.HasSuffix(strings.TrimRight(etag, "\""), *token) {
			return etag
		}
		if idx := strings.LastIndex(etag, "\""); idx != -1 {
			etag = etag[:idx] + *token + "\""
		} else {
			etag += *token
		}
	}

	return etag
}

func StripETagSuffix(etag string) string {
	if token := CurrentEtagToken(); token != nil {
		if strings.HasSuffix(etag, *token+"\"") {
			return strings.TrimSuffix(etag, *token+"\"") + "\""
		} else if strings.HasSuffix(etag, *token) {
			return strings.TrimSuffix(etag, *token)
		}
	}

	return etag
}

func IsRedirect(statusCode int) bool {
	switch statusCode {
	case 301, 302, 303, 307, 308:
		return true
	}

	return false
}

func RedirectedURL(orig *http.Request, requestedUrl *url.URL, redir *url.URL) *url.URL {
	if len(redir.Scheme) > 0 {
		return redir
	} else {
		var host string
		if len(requestedUrl.Host) > 0 {
			host = requestedUrl.Host
		} else if len(orig.Host) > 0 {
			host = orig.Host
		}
		if strings.Index(redir.Path, "/") == 0 {
			newUrl := &url.URL{
				Scheme:      orig.URL.Scheme,
				Opaque:      orig.URL.Opaque,
				User:        orig.URL.User,
				Host:        host,
				Path:        redir.Path,
				RawPath:     redir.RawPath,
				ForceQuery:  redir.ForceQuery,
				RawQuery:    redir.RawQuery,
				Fragment:    redir.Fragment,
				RawFragment: redir.RawFragment,
			}
			return newUrl
		} else {
			splitBy := func(c rune) bool {
				return c == '/'
			}
			origSplat := strings.FieldsFunc(orig.URL.Path, splitBy)
			var newPath string
			if len(origSplat) > 1 {
				newPath = "/" + strings.Join(origSplat[:len(origSplat)-1], "/") + redir.Path
			} else {
				newPath = "/" + redir.Path
			}
			newUrl := &url.URL{
				Scheme:      orig.URL.Scheme,
				Opaque:      orig.URL.Opaque,
				User:        orig.URL.User,
				Host:        host,
				Path:        newPath,
				ForceQuery:  redir.ForceQuery,
				RawQuery:    redir.RawQuery,
				Fragment:    redir.Fragment,
				RawFragment: redir.RawFragment,
			}
			newUrl.RawPath = newUrl.EscapedPath()
			return newUrl
		}
	}
}

func AllowHeaders(h http.Header, allowlist []string) http.Header {
	deleted := []string{}
	for k, _ := range h {
		found := false
		for _, wk := range allowlist {
			if strings.ToLower(k) == wk {
				found = true
				break
			}
		}
		if !found {
			deleted = append(deleted, k)
		}
	}
	out := h.Clone()
	for _, k := range deleted {
		out.Del(k)
	}
	return out
}

func DenyHeaders(h http.Header, denylist []string) http.Header {
	deleted := []string{}
	for k, _ := range h {
		found := false
		for _, wk := range denylist {
			if strings.ToLower(k) == wk {
				found = true
				break
			}
		}
		if found {
			deleted = append(deleted, k)
		}
	}
	out := h.Clone()
	for _, k := range deleted {
		out.Del(k)
	}
	return out
}
