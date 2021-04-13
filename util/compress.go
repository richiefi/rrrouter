package util

import (
	"compress/gzip"
	"github.com/itchio/go-brotli/enc"
	"io"
	"strings"
)

type Recompression struct {
	Add    CompressionType
	Remove CompressionType
}

type CompressionType int

const (
	CompressionTypeNone   CompressionType = 0
	CompressionTypeGzip   CompressionType = 1
	CompressionTypeBrotli CompressionType = 2
)

func NewGzipDecodingReader(body io.ReadCloser) (io.ReadCloser, error) {
	gzReader, err := gzip.NewReader(body)
	if err != nil {
		return nil, err
	}
	return gzReader, nil
}

func NewBrotliEncodingWriter(w io.Writer, compressionLevel int) io.WriteCloser {
	if compressionLevel < 0 || compressionLevel > 11 {
		compressionLevel = 0
	}

	return enc.NewBrotliWriter(w, &enc.BrotliWriterOptions{
		Quality: compressionLevel,
		LGWin:   0,
	})
}

func NewGzipEncodingWriter(w io.Writer, compressionLevel int) (io.WriteCloser, error) {
	if compressionLevel < gzip.BestSpeed || compressionLevel > gzip.BestCompression {
		compressionLevel = gzip.DefaultCompression
	}

	w, err := gzip.NewWriterLevel(w, compressionLevel)
	if err != nil {
		return nil, err
	}
	wCloser, ok := w.(io.WriteCloser)
	if !ok {
		panic("Gzip writer is not an io.Closer")
	}
	return wCloser, nil
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

func GetRecompression(acceptEncoding string, contentEncoding string, contentType string) Recompression {
	switch acceptsEncodingFromString(acceptEncoding) {
	case acceptsBrotli:
		switch contentEncoding {
		case "br":
			return Recompression{Add: CompressionTypeNone, Remove: CompressionTypeNone}
		case "gzip":
			return Recompression{Add: CompressionTypeBrotli, Remove: CompressionTypeGzip}
		default:
			return fallbackCompressionWithDefault(contentEncoding, contentType, CompressionTypeBrotli)
		}
	case acceptsGzip:
		switch contentEncoding {
		case "gzip":
			return Recompression{Add: CompressionTypeNone, Remove: CompressionTypeNone}
		case "br":
			return Recompression{Add: CompressionTypeBrotli, Remove: CompressionTypeNone}
		default:
			return fallbackCompressionWithDefault(contentEncoding, contentType, CompressionTypeGzip)
		}
	case acceptsBrokenClient:
		if contentEncoding == "gzip" {
			return Recompression{Add: CompressionTypeNone, Remove: CompressionTypeGzip}
		}
		return Recompression{Add: CompressionTypeNone, Remove: CompressionTypeNone} // Handle this differently from default, as default might change. Broken client does not change.
	case acceptsOther:
		break
	}

	return fallbackCompressionWithDefault(contentEncoding, contentType, CompressionTypeNone)
}

type acceptsEncoding int

const (
	acceptsOther        acceptsEncoding = 0
	acceptsGzip         acceptsEncoding = 1
	acceptsBrotli       acceptsEncoding = 2
	acceptsBrokenClient acceptsEncoding = 3
)

func acceptsEncodingFromString(s string) acceptsEncoding {
	if strings.Contains(s, ";") {
		return acceptsBrokenClient
	} else if strings.Contains(s, "br") {
		return acceptsBrotli
	} else if strings.Contains(s, "gzip") {
		return acceptsGzip
	}

	return acceptsOther
}

func fallbackCompressionWithDefault(contentEncoding string, contentType string, def CompressionType) Recompression {
	if (contentEncoding == "" || contentEncoding == "identity") && (contentType == "application/json" || strings.HasPrefix(contentType, "text/")) {
		return Recompression{Add: def, Remove: CompressionTypeNone}
	}

	return Recompression{Add: CompressionTypeNone, Remove: CompressionTypeNone}
}
