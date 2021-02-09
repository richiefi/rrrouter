package caching

import (
	"encoding/json"
	"fmt"
	apexlog "github.com/apex/log"
	"github.com/c2h5oh/datasize"
	"github.com/richiefi/rrrouter/yamlconfig"
	"hash/adler32"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Cache interface {
	Get(string, Key, http.ResponseWriter, *apexlog.Logger) (CacheResult, error)
	HasStorage(string) bool
	Invalidate(Key, *apexlog.Logger)
}

func NewCacheWithOptions(opts []StorageConfiguration, logger *apexlog.Logger, now func() time.Time, closeNotifier *chan string) Cache {
	storages := make([]*Storage, 0, len(opts))
	for _, o := range opts {
		s := NewDiskStorage(o.Id, o.Path, int64(o.Size), logger, now)
		storages = append(storages, &s)
	}

	if now == nil {
		now = time.Now
	}

	c := &cache{
		storages:           storages,
		waitingReaders:     make(map[string][]*chan bool, 10),
		waitingReadersLock: sync.Mutex{},
		logger:             logger,
		now:                now,
		closeNotifier:      closeNotifier,
	}

	closeNotif := make(chan string)
	c.closeNotifier = &closeNotif

	go c.readerNotifier()

	return c
}

type cache struct {
	Cache
	waitingReaders     map[string][]*chan bool
	waitingReadersLock sync.Mutex
	storages           []*Storage
	logger             *apexlog.Logger
	now                func() time.Time
	closeNotifier      *chan string
}

func (c *cache) readerNotifier() {
	if c.closeNotifier == nil {
		return
	}

	for {
		c.logger.Debugf("readerNotifier waiting for key")
		rk := <-*c.closeNotifier
		c.logger.Debugf("readerNotifier got key: %v", rk)
		c.waitingReadersLock.Lock()
		if readers, exists := c.waitingReaders[rk]; exists {
			for i, r := range readers {
				c.logger.Debugf("readerNotifier notifying %v %v", i, r)
				*r <- true
			}
			delete(c.waitingReaders, rk)
		}
		c.waitingReadersLock.Unlock()
	}
}

func (c *cache) Get(cacheId string, k Key, w http.ResponseWriter, logctx *apexlog.Logger) (CacheResult, error) {
	s := c.storageWithCacheId(cacheId)
	rc, sm, err := (*s).Get(k)
	if err != nil {
		if !os.IsNotExist(err) {
			c.logger.WithField("error", err).Error(fmt.Sprintf("Storage %v errored when fetching key %v\n", (*s).Id(), k.FsName()))
			return CacheResult{Kind: NotFoundReader, Reader: nil, Writer: nil, Metadata: CacheMetadata{}, Age: 0, ShouldRevalidate: false}, err
		}

		rk := k.FsName()
		c.waitingReadersLock.Lock()
		if _, exists := c.waitingReaders[rk]; exists {
			wc := make(chan bool)
			defer c.waitingReadersLock.Unlock()
			c.waitingReaders[rk] = append(c.waitingReaders[rk], &wc)
			c.logger.Debugf("Locking for reader: %v", k)
			return CacheResult{NotFoundReader, nil, nil, &wc, CacheMetadata{}, 0, false}, nil
		} else {
			c.waitingReaders[rk] = make([]*chan bool, 0)
			defer c.waitingReadersLock.Unlock()
			writer := NewCachingResponseWriter(w, c.getWriter(cacheId, k, false), logctx)
			c.logger.Debugf("Locking for writer: %v", k)
			return CacheResult{NotFoundWriter, nil, writer, nil, CacheMetadata{}, 0, false}, nil
		}
	}

	var age int64
	if sm.Revalidated != 0 {
		age = c.now().Unix() - sm.Revalidated
	} else {
		age = c.now().Unix() - sm.Created
	}

	if etag := k.originalHeaders.Get("if-none-match"); len(etag) > 0 {
		if normalizeEtag(etag) == normalizeEtag(sm.ResponseHeader.Get("etag")) {
			defer rc.Close()
			return CacheResult{Found, nil, nil, nil, CacheMetadata{Header: sm.ResponseHeader, Status: 304, Size: 0}, age, false}, nil
		}
	}

	shouldRevalidate := false
	expires := sm.ResponseHeader.Get("expires")
	var expiresTime time.Time
	if len(expires) > 0 {
		expiresTime = c.now()
		for _, f := range []string{time.RFC1123, time.RFC1123Z} {
			var err error
			expiresTime, err = time.Parse(f, expires)
			if err != nil {
				continue
			}
			break
		}
		shouldRevalidate = expiresTime.Unix() <= c.now().Unix()
	}

	dirs := GetCacheControlDirectives(sm.ResponseHeader)
	if !shouldRevalidate {
		if dirs.SMaxAge != nil {
			shouldRevalidate = *dirs.SMaxAge <= age
		} else if dirs.MaxAge != nil {
			shouldRevalidate = *dirs.MaxAge <= age
		}
	}

	if shouldRevalidate {
		writer := NewCachingResponseWriter(w, c.getWriter(cacheId, k, true), logctx)
		return CacheResult{Found, rc, writer, nil, CacheMetadata{Header: sm.ResponseHeader, Status: sm.Status, Size: sm.Size}, age, true}, nil
	}

	return CacheResult{Found, rc, nil, nil, CacheMetadata{Header: sm.ResponseHeader, Status: sm.Status, Size: sm.Size}, age, false}, nil
}

func (c *cache) HasStorage(id string) bool {
	return c.storageWithCacheId(id) != nil
}

func (c *cache) Invalidate(k Key, l *apexlog.Logger) {
	if c.closeNotifier == nil {
		return
	}

	*c.closeNotifier <- k.FsName()
}

func (c *cache) getWriter(cacheId string, k Key, revalidate bool) CacheWriter {
	var s *Storage
	if s = c.storageWithCacheId(cacheId); s == nil {
		s = c.defaultStorage()
	}

	cw, ok := (*s).GetWriter(k, revalidate, c.closeNotifier).(CacheWriter)
	if !ok {
		return nil
	}

	return cw
}

func (c *cache) storageWithCacheId(cacheId string) *Storage {
	for _, s := range c.storages {
		if (*s).Id() == cacheId {
			return s
		}
	}

	return nil
}

func (c *cache) defaultStorage() *Storage {
	for _, s := range c.storages {
		return s
	}

	panic("Caching in use, but no backing storage found")
}

type Key struct {
	host            string
	path            string
	storedHeaders   http.Header
	originalHeaders http.Header
}

func KeyFromRequest(r *http.Request) Key {
	return Key{host: r.Host, path: r.URL.Path, storedHeaders: allowHeaders(r.Header, keyClientHeaders), originalHeaders: r.Header}
}

func (k Key) FsName() string {
	hs := ""
	for k, vv := range k.storedHeaders {
		vs := ""
		for _, v := range vv {
			vs += v
		}
		hs += k + vs
	}
	s := k.host + k.path + hs
	return strconv.Itoa(int(adler32.Checksum([]byte(s))))
}

var keyClientHeaders = []string{"host", "accept-encoding", "origin"}
var HeaderRrrouterCacheStatus = "rrrouter-cache-status"

type cacheConfig struct {
	Storages []storageConfiguration `json:"caches"`
}

type storageConfiguration struct {
	Size string `json:"size"`
	Path string `json:"path"`
	Id   string `json:"id"`
}

type StorageConfiguration struct {
	Size datasize.ByteSize
	Path string
	Id   string
}

type CacheMetadata struct {
	Header http.Header
	Status int
	Size   int64
}

type CacheResultKind int

const (
	Found CacheResultKind = iota
	NotFoundWriter
	NotFoundReader
)

type CacheResult struct {
	Kind             CacheResultKind
	Reader           *os.File
	Writer           CachingResponseWriter
	WaitChan         *chan bool
	Metadata         CacheMetadata
	Age              int64
	ShouldRevalidate bool
}

type Writer interface {
	io.WriteCloser
	Flush()
}

type CacheItemOptions struct {
	Revalidate int
}

type CacheWriter interface {
	io.WriteCloser
	http.Flusher
	WriteHeader(statusCode int, header http.Header)
	Abort() error
	WrittenFile() (*os.File, error)
}

func ParseStorageConfigs(cfg []byte) ([]StorageConfiguration, error) {
	var cc cacheConfig
	jsonbytes, err := yamlconfig.Convert(cfg)
	if err != nil {
		err = json.Unmarshal(cfg, &cc)
	} else {
		err = json.Unmarshal(jsonbytes, &cc)
	}
	if err != nil {
		return nil, fmt.Errorf("error parsing storages configuration: %s", err)
	}

	configs := []StorageConfiguration{}
	for _, s := range cc.Storages {
		if len(s.Path) == 0 || len(s.Id) == 0 {
			continue
		}
		for _, c := range configs {
			if c.Path == s.Path || c.Id == s.Id {
				panic(fmt.Sprintf("Two storages share the same path or id. %v, %v. Can't continue.", s.Path, s.Id))
			}
		}
		var v datasize.ByteSize
		err := v.UnmarshalText([]byte(s.Size))
		if err == nil {
			configs = append(configs, StorageConfiguration{Size: v, Path: s.Path, Id: s.Id})
		}
	}

	return configs, nil
}

type CachingResponseWriter interface {
	http.ResponseWriter
	http.Flusher
	Abort() error
	WrittenFile() (*os.File, error)
	GetClientWriter() http.ResponseWriter
}

type cachingResponseWriter struct {
	clientWriter        http.ResponseWriter
	clientBytesLeft     int64
	cacheWriter         CacheWriter
	cacheWriterFinished bool
	log                 *apexlog.Logger
}

func (crw *cachingResponseWriter) Header() http.Header {
	return crw.clientWriter.Header()
}

func (crw *cachingResponseWriter) Write(ba []byte) (int, error) {
	return crw.cacheWriter.Write(ba)
}

func (crw *cachingResponseWriter) WriteHeader(statusCode int) {
	crw.clientWriter.WriteHeader(statusCode)
	var cleanedHeaders http.Header
	if statusCode == 206 {
		statusCode = 200 // We don't write partial content to storage
		cl := contentLengthFromRange(crw.clientWriter.Header().Get("content-range"))
		cleanedHeaders = denyHeaders(crw.clientWriter.Header(), []string{"content-range"})
		if len(cl) > 0 {
			cleanedHeaders.Set("content-length", cl)
		}

	}
	if statusCode == 200 && crw.cacheWriter != nil {
		if cleanedHeaders != nil {
			crw.cacheWriter.WriteHeader(statusCode, cleanedHeaders)
		} else {
			crw.cacheWriter.WriteHeader(statusCode, crw.clientWriter.Header())
		}
	}
}

func (crw *cachingResponseWriter) Flush() {
	crw.cacheWriter.Flush()
}

func (crw *cachingResponseWriter) Close() error {
	return crw.cacheWriter.Close()
}

func (crw *cachingResponseWriter) WrittenFile() (*os.File, error) {
	return crw.cacheWriter.WrittenFile()
}

func (crw *cachingResponseWriter) GetClientWriter() http.ResponseWriter {
	return crw.clientWriter
}

func (crw *cachingResponseWriter) Abort() error {
	err := crw.cacheWriter.Abort()
	if err != nil {
		crw.log.WithField("error", err).Error("Could not clean up stray file after error")
	}

	return nil
}

func NewCachingResponseWriter(w http.ResponseWriter, cw CacheWriter, logctx *apexlog.Logger) CachingResponseWriter {
	return &cachingResponseWriter{
		clientWriter: w,
		cacheWriter:  cw,
		log:          logctx,
	}
}

// Helper functions

func allowHeaders(h http.Header, allowlist []string) http.Header {
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

func denyHeaders(h http.Header, denylist []string) http.Header {
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

func normalizeEtag(s string) string {
	return strings.TrimLeft("W/", s)
}

type CacheControlDirectives struct {
	NoCache bool
	NoStore bool
	MaxAge  *int64
	SMaxAge *int64
	Private bool
}

func (ccd CacheControlDirectives) DoNotCache() bool {
	return ccd.Private || ccd.NoStore || (ccd.SMaxAge != nil && *ccd.SMaxAge == 0) || (ccd.MaxAge != nil && *ccd.MaxAge == 0)
}

func GetCacheControlDirectives(h http.Header) CacheControlDirectives {
	ds := allHeaderValues("cache-control", h)
	dirs := CacheControlDirectives{}
	for _, dd := range ds {
		for _, d := range strings.Split(dd, ",") {
			if strings.Contains(d, "=") {
				kv := strings.Split(d, "=")
				if len(kv) != 2 {
					continue
				}
				k := strings.Trim(kv[0], " ")
				v := strings.Trim(kv[1], " ")
				switch k {
				case "max-age":
					maxAge, err := strconv.Atoi(v)
					if err == nil {
						maxAge64 := int64(maxAge)
						dirs.MaxAge = &maxAge64
					}
				case "s-maxage":
					sMaxAge, err := strconv.Atoi(v)
					if err == nil {
						sMaxAge64 := int64(sMaxAge)
						dirs.SMaxAge = &sMaxAge64
					}
				}
			} else {
				d = strings.Trim(d, " ")
				switch d {
				case "private":
					dirs.Private = true
				case "no-cache":
					dirs.NoCache = true
				case "no-store":
					dirs.NoStore = true
				}
			}
		}
	}

	return dirs
}

func allHeaderValues(k string, h http.Header) []string {
	vals := []string{}
	for _, vs := range h.Values(k) {
		for _, s := range strings.Split(vs, ",") {
			s = strings.Trim(s, " ")
			vals = append(vals, strings.ToLower(s))
		}
	}
	return vals
}

func contentLengthFromRange(s string) string {
	splat := strings.Split(s, "/")
	if len(splat) != 2 {
		return ""
	}

	_, err := strconv.Atoi(splat[1])
	if err != nil {
		return ""
	}

	return splat[1]
}
