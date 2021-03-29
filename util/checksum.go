package util

import (
	"crypto/sha1"
	"encoding/hex"
)

func SHA1String(bs []byte) string {
	h := sha1.New()
	h.Write(bs)
	return hex.EncodeToString(h.Sum(nil))
}
