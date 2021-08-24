package util

import (
	"net"
	"net/http"
	"strings"
)

// DropPort returns an URL without the port part
func DropPort(ipport string) string {
	if len(ipport) == 0 {
		return ipport
	}

	if ipport[0] == '[' { //ipv6 looks like [addr]:port
		closeBracketIndex := strings.LastIndex(ipport, "]")
		ip := ipport[1:closeBracketIndex]
		return ip
	} else if ipport[0] != ':' {
		lastColonIndex := strings.LastIndex(ipport, ":")
		if lastColonIndex == -1 {
			return ipport
		}
		ip := ipport[0:lastColonIndex]
		return ip
	} else {
		return ipport
	}
}

// RequestIP parses CF-Connecting-IP, X-Real-Ip and X-Forwarded-For headers to determine the original client IP
func RequestIP(req *http.Request) string {
	cfip := req.Header.Get("cf-connecting-ip")
	if cfip != "" {
		return cfip
	}

	clientIP := strings.TrimSpace(req.Header.Get("X-Real-Ip"))
	if len(clientIP) > 0 {
		return DropPort(clientIP)
	}
	clientIP = req.Header.Get("X-Forwarded-For")
	if index := strings.IndexByte(clientIP, ','); index >= 0 {
		clientIP = clientIP[0:index]
	}
	clientIP = strings.TrimSpace(clientIP)
	if len(clientIP) > 0 {
		return DropPort(clientIP)
	}
	if ip, _, err := net.SplitHostPort(strings.TrimSpace(req.RemoteAddr)); err == nil {
		return DropPort(ip)
	}

	return ""
}
