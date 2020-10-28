package util

import (
	"compress/gzip"
	"github.com/itchio/go-brotli/enc"
	"io"
	"strings"
)

type CompressionType int

const (
	CompressionTypeNone    CompressionType = 0
	CompressionTypeGzip    CompressionType = 1
	CompressionTypeBrotli  CompressionType = 2
)

func NewGzipDecodingReader(body io.ReadCloser) (io.ReadCloser, error) {
	gzReader, err := gzip.NewReader(body)
	if (err != nil) {
		return nil, err
	}
	return gzReader, nil
}

func NewBrotliEncodingWriter(w io.Writer) io.Writer {
	return enc.NewBrotliWriter(w, &enc.BrotliWriterOptions{
		Quality: 0,
		LGWin:   0,
	})
}

func NewGzipEncodingWriter(w io.Writer) io.Writer {
	return gzip.NewWriter(w)
}

func ContentEncodingFromCompressionType(compressionType CompressionType) string {
	switch compressionType {
	case CompressionTypeGzip:
		return "gzip"
	case CompressionTypeBrotli:
		return "br"
	default:
		return ""
	}
}

func GetAddCompressionType(acceptEncoding string, contentEncoding string, contentType string) CompressionType {
	switch acceptsEncodingFromString(acceptEncoding) {
	case acceptsBrotli:
		switch contentEncoding {
		case "br":
			return CompressionTypeNone
		case "gzip":
			return CompressionTypeBrotli
		default:
			return fallbackCompressionWithDefault(contentEncoding, contentType, CompressionTypeBrotli)
		}
	case acceptsGzip:
		switch contentEncoding {
		case "gzip":
			return CompressionTypeNone
		case "br":
			return CompressionTypeBrotli
		default:
			return fallbackCompressionWithDefault(contentEncoding, contentType, CompressionTypeGzip)
		}
	case acceptsOther:
		break
	}

	return fallbackCompressionWithDefault(contentEncoding, contentType, CompressionTypeNone)
}

type acceptsEncoding int
const (
	acceptsOther  acceptsEncoding = 0
	acceptsGzip   acceptsEncoding = 1
	acceptsBrotli acceptsEncoding = 2
)

func acceptsEncodingFromString(s string) acceptsEncoding {
	if strings.Contains(s, "br") {
		return acceptsBrotli
	} else if strings.Contains(s, "gzip") {
		return acceptsGzip
	}

	return acceptsOther
}

func fallbackCompressionWithDefault(contentEncoding string, contentType string, def CompressionType) CompressionType {
	if (contentEncoding == "" || contentEncoding == "identity") && (contentType == "application/json" || strings.HasPrefix(contentType, "text/")) {
		return def
	}

	return CompressionTypeNone
}

