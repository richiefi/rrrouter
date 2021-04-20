package util

import (
	"net/http"
	"net/url"
	"strings"
)

func IsRedirect(statusCode int) bool {
	switch statusCode {
	case 301, 302, 303, 307, 308:
		return true
	}

	return false
}

func RedirectedURL(orig *url.URL, redir *url.URL) *url.URL {
	if len(redir.Scheme) > 0 {
		return redir
	} else if strings.Index(redir.Path, "/") == 0 {
		newUrl := &url.URL{
			Scheme:      orig.Scheme,
			Opaque:      orig.Opaque,
			User:        orig.User,
			Host:        orig.Host,
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
		origSplat := strings.FieldsFunc(orig.Path, splitBy)
		var newPath string
		if len(origSplat) > 1 {
			newPath = "/" + strings.Join(origSplat[:len(origSplat)-1], "/") + redir.Path
		} else {
			newPath = "/" + redir.Path
		}
		newUrl := &url.URL{
			Scheme:      orig.Scheme,
			Opaque:      orig.Opaque,
			User:        orig.User,
			Host:        orig.Host,
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
