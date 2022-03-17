package util

import (
	"net/http"
	"net/url"
	"strings"
)

var HeadersAllowedIn304 = []string{"cache-control", "content-location", "date", "etag", "last-modified", "expires", "vary", "richie-edge-cache"}

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

// RevalidateHeaders returns a pair of revalidation header keys,
// in the order of client key, origin key and its value, if found.
func RevalidateHeaders(h http.Header) (string, string, string) {
	eitherOr := [][]string{{"if-none-match", "etag"}, {"if-modified-since", "last-modified"}}
	for _, tup := range eitherOr {
		if v := h.Get(tup[0]); v != "" {
			return tup[0], tup[1], v
		} else if v = h.Get(tup[1]); v != "" {
			return tup[0], tup[1], v
		}
	}

	return "", "", ""
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
