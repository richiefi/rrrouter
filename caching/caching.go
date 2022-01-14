package caching

import (
	"context"
	"encoding/json"
	"fmt"
	apexlog "github.com/apex/log"
	"github.com/c2h5oh/datasize"
	"github.com/getsentry/sentry-go"
	mets "github.com/richiefi/rrrouter/metrics"
	"github.com/richiefi/rrrouter/util"
	"github.com/richiefi/rrrouter/yamlconfig"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Cache interface {
	Get(context.Context, string, int, bool, []Key, http.ResponseWriter, *apexlog.Logger) (CacheResult, Key, error)
	HasStorage(string) bool
	SetStorageConfigs([]StorageConfiguration)
	Finish(Key, *apexlog.Logger)
	HealthCheck() error
}

func NewCacheWithOptions(opts []StorageConfiguration, logger *apexlog.Logger, now func() time.Time) Cache {
	storages := make([]*Storage, 0, len(opts))
	for _, o := range opts {
		s := NewDiskStorage(o.Id, o.Path, int64(o.Size), logger, now)
		storages = append(storages, &s)
	}

	return newCache(storages, logger, now)
}

func NewCacheWithStorages(storages []*Storage, logger *apexlog.Logger, now func() time.Time) Cache {
	return newCache(storages, logger, now)
}

func newCache(storages []*Storage, logger *apexlog.Logger, now func() time.Time) Cache {
	if now == nil {
		now = time.Now
	}

	c := &cache{
		storages:           storages,
		waitingReaders:     make(map[string][]*chanWithTime, 10),
		waitingReadersLock: sync.Mutex{},
		logger:             logger,
		now:                now,
	}

	closeNotif := make(chan KeyInfo)
	c.closeNotifier = &closeNotif

	go c.readerNotifier()
	s := os.Getenv("DEBUG_NOTIFIER_INTERVAL")
	if i, err := strconv.Atoi(s); err == nil && i > 0 {
		go c.debugReaderNotifier(i)
	}

	return c
}

type cache struct {
	Cache
	waitingReaders     map[string][]*chanWithTime
	waitingReadersLock sync.Mutex
	storages           []*Storage
	logger             *apexlog.Logger
	now                func() time.Time
	closeNotifier      *chan KeyInfo
}

type chanWithTime struct {
	ch          *chan KeyInfo
	originalUrl string
	time        time.Time
}

func (c *cache) readerNotifier() {
	if c.closeNotifier == nil {
		return
	}

	for {
		c.logger.Debugf("readerNotifier (%p) waiting for Key", c.closeNotifier)
		ki := <-*c.closeNotifier
		k := ki.Key
		rk := k.FsName()
		c.logger.Debugf("readerNotifier (%p) got Key: %v / %v", c.closeNotifier, k.host+k.path, rk)
		c.waitingReadersLock.Lock()
		if readers, exists := c.waitingReaders[rk]; exists {
			c.logger.Debugf("readerNotifier (%p) notifying %v (%p) with: %v / %v", c.closeNotifier, len(readers), &c.waitingReaders, k.host+k.path, rk)
			for i, ct := range readers {
				c.logger.Debugf("readerNotifier notifying %v, ch (%p)", i, ct.ch)
				*ct.ch <- ki
			}
			delete(c.waitingReaders, rk)
		} else {
			c.logger.Debugf("readerNotifier (%p) nothing to notify: %v / %v", c.closeNotifier, k.host+k.path, rk)
		}
		c.waitingReadersLock.Unlock()
	}
}

func (c *cache) debugReaderNotifier(i int) {
	for {
		c.logger.Infof("rn: enter")
		c.waitingReadersLock.Lock()
		ages := []time.Duration{}
		n := len(c.waitingReaders)
		if n == 0 {
			c.waitingReadersLock.Unlock()
			c.logger.Infof("rn: exit 0")
			time.Sleep(time.Second * time.Duration(i))
			continue
		}
		for rk, cts := range c.waitingReaders {
			url := ""
			if len(cts) > 0 {
				url = cts[0].originalUrl
			}
			c.logger.Infof("rn: %v has %v waiting, url: %v", rk, len(cts), url)
			stale := false
			for _, ct := range cts {
				age := time.Now().Sub(ct.time)
				if age > time.Second*90 {
					stale = true
					c.logger.Infof("rn: %v with age %v, url: %v", rk, age, ct.originalUrl)
				}
				ages = append(ages, age)
			}
			if stale {
				sentry.CaptureMessage(fmt.Sprintf("rn: stale: %v, url: %v", rk, url))
			}

		}
		if len(ages) > 0 {
			sum := 0
			max := 0
			for age := range ages {
				if age > max {
					max = age
				}
				sum += age
			}
			c.logger.Infof("rn: %v keys in total with avg: %v, max: %v", n, sum/len(ages), max)
		} else {
			c.logger.Infof("rn: %v keys in total with none waiting", n)
		}
		c.waitingReadersLock.Unlock()
		c.logger.Infof("rn: exit")
		time.Sleep(time.Second * 5)
	}
}

func notFoundPreferredKey(keys []Key) Key {
	for _, k := range keys {
		if k.opaqueOrigin {
			return k
		}
	}

	return keys[0]
}

func (c *cache) Get(ctx context.Context, cacheId string, forceRevalidate int, skipRevalidate bool, keys []Key, w http.ResponseWriter, logctx *apexlog.Logger) (CacheResult, Key, error) {
	defer mets.FromContext(ctx).MarkTime(time.Now())
	s := c.storageWithCacheId(cacheId)
	rc, sm, k, err := (*s).Get(ctx, keys)
	if err != nil {
		if !os.IsNotExist(err) {
			c.logger.WithField("error", err).Error(fmt.Sprintf("Storage %v errored when fetching Key %v\n", (*s).Id(), k.FsName()))
			return CacheResult{Kind: NotFoundReader, Reader: nil, Writer: nil, Metadata: CacheMetadata{}, Age: 0, IsStale: false}, k, err
		}
		k = notFoundPreferredKey(keys)
		//logctx.Debugf("Miss: %v // %v", k, k.FsName())
		cr := c.getReaderOrWriter(ctx, cacheId, k, w, false, false, logctx)
		return cr, k, nil
	}

	//logctx.Debugf("Hit: %v // %v", k, k.FsName())

	var age int64
	ageFromRevalidate := false
	if sm.Revalidated != 0 {
		age = c.now().Unix() - sm.Revalidated
		ageFromRevalidate = true
	} else {
		age = c.now().Unix() - sm.Created
	}

	shouldRevalidate := false
	if forceRevalidate != 0 {
		shouldRevalidate = age >= int64(forceRevalidate)
		skipRevalidate = false
	}

	dirs := GetCacheControlDirectives(sm.ResponseHeader)
	if !shouldRevalidate {
		if dirs.SMaxAge != nil {
			shouldRevalidate = *dirs.SMaxAge <= age
		} else if dirs.MaxAge != nil {
			shouldRevalidate = *dirs.MaxAge <= age
		}
	}

	expires := sm.ResponseHeader.Get("expires")
	var expiresTime time.Time
	if !shouldRevalidate && len(expires) > 0 && !ageFromRevalidate {
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

	if !shouldRevalidate {
		if etag := k.originalHeaders.Get("if-none-match"); len(etag) > 0 {
			if normalizeEtag(etag) == normalizeEtag(sm.ResponseHeader.Get("etag")) {
				defer rc.Close()
				return CacheResult{Found, nil, nil, nil, CacheMetadata{Header: sm.ResponseHeader, Status: 304, Size: 0}, age, false}, k, nil
			}
		} else if modifiedSince := k.originalHeaders.Get("if-modified-since"); len(modifiedSince) > 0 {
			mdModifiedSince := sm.ResponseHeader.Get("last-modified")
			if mdModifiedSince == modifiedSince {
				defer rc.Close()
				return CacheResult{Found, nil, nil, nil, CacheMetadata{Header: sm.ResponseHeader, Status: 304, Size: 0}, age, false}, k, nil
			}
		}
	}

	isStale := shouldRevalidate
	if shouldRevalidate && skipRevalidate {
		shouldRevalidate = false
	}

	if shouldRevalidate {
		err := rc.Close()
		if err != nil {
			logctx.WithError(err).Errorf("Could not close an optimistically opened fd, which then had to be revalidated")
		}

		cr := c.getReaderOrWriter(ctx, cacheId, k, w, true, dirs.CanStaleWhileRevalidate(age), logctx)
		cr.Metadata = CacheMetadata{Header: sm.ResponseHeader, Status: sm.Status, Size: sm.Size, FdSize: sm.FdSize, RedirectedURL: sm.RedirectedURL}
		cr.Age = age
		return cr, k, nil
	}

	return CacheResult{Found, rc, nil, nil, CacheMetadata{Header: sm.ResponseHeader, Status: sm.Status, Size: sm.Size, FdSize: sm.FdSize, RedirectedURL: sm.RedirectedURL}, age, isStale}, k, nil
}

func (c *cache) getReaderOrWriter(ctx context.Context, cacheId string, k Key, w http.ResponseWriter, isRevalidating bool, staleWhileRevalidate bool, logctx *apexlog.Logger) CacheResult {
	rk := k.FsName()
	c.waitingReadersLock.Lock()
	//c.logger.Debugf("Checking if %v exists", rk)
	var kind CacheResultKind
	if _, exists := c.waitingReaders[rk]; exists {
		if isRevalidating && staleWhileRevalidate {
			c.waitingReadersLock.Unlock()
			c.logger.Debugf("Released lock for stale reader attempt: %v", rk)
			cr, _, _ := c.Get(ctx, cacheId, 0, true, []Key{k}, w, logctx)
			return cr
		}
		defer c.waitingReadersLock.Unlock()
		wc := make(chan KeyInfo, 1)
		ct := chanWithTime{
			ch:          &wc,
			originalUrl: k.host + k.path,
			time:        time.Now(),
		}
		c.waitingReaders[rk] = append(c.waitingReaders[rk], &ct)
		c.logger.Debugf("Locking for reader %v, ch (%p)", rk, &wc)
		if isRevalidating {
			kind = RevalidatingReader
		} else {
			kind = NotFoundReader
		}
		return CacheResult{kind, nil, nil, &wc, CacheMetadata{}, 0, false}
	} else {
		c.waitingReaders[rk] = make([]*chanWithTime, 0)
		defer c.waitingReadersLock.Unlock()
		writer := NewCachingResponseWriter(w, c.getWriter(cacheId, k, isRevalidating), logctx)
		c.logger.Debugf("Locking for writer: %v", rk)
		if isRevalidating {
			kind = RevalidatingWriter
		} else {
			kind = NotFoundWriter
		}
		return CacheResult{kind, nil, writer, nil, CacheMetadata{}, 0, false}

	}
}

func (c *cache) HasStorage(id string) bool {
	return c.storageWithCacheId(id) != nil
}

func (c *cache) SetStorageConfigs(cfgs []StorageConfiguration) {
	storages := make([]*Storage, 0, len(cfgs))
	for _, cfg := range cfgs {
		existing := c.storageWithCacheId(cfg.Id)
		if existing != nil {
			(*existing).Update(cfg)
		} else {
			s := NewDiskStorage(cfg.Id, cfg.Path, int64(cfg.Size), c.logger, c.now)
			storages = append(storages, &s)
		}
	}
	if len(storages) == 0 {
		return
	}
	for _, s := range c.storages {
		found := false
		for _, newStorage := range storages {
			if (*newStorage).Id() == (*s).Id() {
				found = true
			}
		}
		if !found {
			(*s).SetIsReplaced()
		}
	}
	c.storages = storages
}

func (c *cache) Finish(k Key, l *apexlog.Logger) {
	if c.closeNotifier == nil {
		l.Infof("cache.Finish: c.closeNotifier is nil")
		return
	}

	l.Debugf("cache.Finish: %v / %v. %p", k.host+k.path, k.FsName(), c.closeNotifier)
	*c.closeNotifier <- KeyInfo{Key: k}
}

func (c *cache) HealthCheck() error {
	for _, s := range c.storages {
		if ok, err := (*s).WriteTest(); !ok {
			return err
		}
	}

	return nil
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
	method          string
	host            string
	path            string
	opaqueOrigin    bool
	storedHeaders   http.Header
	originalHeaders http.Header
}

func KeysFromRequest(r *http.Request) []Key {
	keys := make([]Key, 0)
	method := ""
	if r.Method != "GET" {
		method = r.Method
	}
	if len(r.Header.Get("origin")) > 0 {
		k := newKey(method, r.Host, r.URL.RequestURI(), false, r.Header, append(keyClientHeaders, "origin"))
		keys = append(keys, k)
		k = newKey(method, r.Host, r.URL.RequestURI(), true, r.Header, keyClientHeaders)
		keys = append(keys, k)
	} else {
		k := newKey(method, r.Host, r.URL.RequestURI(), false, r.Header, keyClientHeaders)
		keys = append(keys, k)
	}

	return keys
}

func newKey(method string, host string, path string, opaqueOrigin bool, originalHeaders http.Header, allowHeaderKeys []string) Key {
	k := Key{method: method, host: host, path: path, opaqueOrigin: opaqueOrigin, storedHeaders: util.AllowHeaders(originalHeaders, allowHeaderKeys), originalHeaders: originalHeaders}
	return k
}

func (k Key) FsName() string {
	headerKeys := make([]string, 0)
	hs := ""
	for hk, _ := range k.storedHeaders {
		headerKeys = append(headerKeys, hk)
	}
	sort.Strings(headerKeys)
	for _, hk := range headerKeys {
		hs += hk
		for _, v := range k.storedHeaders[hk] {
			hs += v
		}
	}
	s := k.method + k.host + k.path + hs
	if k.opaqueOrigin {
		s += "opaqueOrigin"
	}
	name := util.SHA1String([]byte(s))
	return prefixWithItemName(name) + name
}

func prefixWithItemName(s string) string {
	prefix := ""
	for _, c := range s[:3] {
		prefix += string(c) + "/"
	}

	return prefix
}

func (k Key) HasOpaqueOrigin() bool {
	return k.opaqueOrigin
}

func (k Key) HasFullOrigin() bool {
	return k.opaqueOrigin == false && len(k.storedHeaders.Get("origin")) > 0
}

var keyClientHeaders = []string{"host", "accept-encoding", "authorization"}
var HeaderRrrouterCacheStatus = "richie-edge-cache"

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
	Header        http.Header
	Status        int
	Size          int64
	FdSize        int64
	RedirectedURL string
}

type CacheResultKind int

const (
	Found CacheResultKind = iota
	NotFoundWriter
	NotFoundReader
	RevalidatingWriter
	RevalidatingReader
)

type CacheResult struct {
	Kind     CacheResultKind
	Reader   *os.File
	Writer   CachingResponseWriter
	WaitChan *chan KeyInfo
	Metadata CacheMetadata
	Age      int64
	IsStale  bool
}

type KeyInfo struct {
	Key         Key
	CanUseStale bool
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
	SetRedirectedURL(redir *url.URL)
	SetRevalidated()
	SetRevalidateErrored(bool)
	ChangeKey(Key) error
	Delete() error
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
	Delete() error
	WrittenFile() (*os.File, error)
	ChangeKey(Key) error
	GetClientWriter() http.ResponseWriter
	ReadFrom(r io.Reader) (n int64, err error)
	SetClientWritesDisabled()
	GetClientWritesDisabled() bool
	SetRedirectedURL(*url.URL)
	SetRevalidatedAndClose() error
	SetRevalidateErroredAndClose(bool) error
}

type cachingResponseWriter struct {
	clientWriter         http.ResponseWriter
	clientWritesDisabled bool
	cacheWriter          CacheWriter
	log                  *apexlog.Logger
}

func (crw *cachingResponseWriter) Header() http.Header {
	return crw.clientWriter.Header()
}

func (crw *cachingResponseWriter) Write(ba []byte) (int, error) {
	return crw.cacheWriter.Write(ba)
}

func (crw *cachingResponseWriter) WriteHeader(statusCode int) {
	if !crw.clientWritesDisabled {
		crw.clientWriter.WriteHeader(statusCode)
	}
	var cleanedHeaders http.Header
	if statusCode == 206 {
		/* We don't write partial content to storage. `range` has been omitted from origin request and only the client
		   is being served with partial content, with HTTP 206. */
		statusCode = 200
		cl := contentLengthFromRange(crw.clientWriter.Header().Get("content-range"))
		cleanedHeaders = util.DenyHeaders(crw.clientWriter.Header(), []string{"content-range"})
		if len(cl) > 0 {
			cleanedHeaders.Set("content-length", cl)
		}
	}
	if crw.cacheWriter != nil {
		if statusCode == 200 || IsCacheableError(statusCode) || util.IsRedirect(statusCode) {
			if cleanedHeaders != nil {
				crw.cacheWriter.WriteHeader(statusCode, cleanedHeaders)
			} else {
				crw.cacheWriter.WriteHeader(statusCode, crw.clientWriter.Header())
			}
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

func (crw *cachingResponseWriter) ChangeKey(k Key) error {
	return crw.cacheWriter.ChangeKey(k)
}

func (crw *cachingResponseWriter) GetClientWriter() http.ResponseWriter {
	return crw.clientWriter
}

func (crw *cachingResponseWriter) SetClientWritesDisabled() {
	crw.clientWritesDisabled = true
}

func (crw *cachingResponseWriter) GetClientWritesDisabled() bool {
	return crw.clientWritesDisabled
}

func (crw *cachingResponseWriter) SetRedirectedURL(redir *url.URL) {
	crw.cacheWriter.SetRedirectedURL(redir)
}

func (crw *cachingResponseWriter) SetRevalidatedAndClose() error {
	crw.cacheWriter.SetRevalidated()
	return crw.cacheWriter.Close()
}

func (crw *cachingResponseWriter) SetRevalidateErroredAndClose(canStaleIfError bool) error {
	crw.cacheWriter.SetRevalidateErrored(canStaleIfError)
	return crw.cacheWriter.Close()
}

func (crw *cachingResponseWriter) Delete() error {
	err := crw.cacheWriter.Delete()
	if err != nil {
		crw.log.WithField("error", err).Error("Could not clean up stray file after error")
	}

	return nil
}

func (crw *cachingResponseWriter) ReadFrom(r io.Reader) (n int64, err error) {
	rf, _ := crw.clientWriter.(io.ReaderFrom)
	return rf.ReadFrom(r)
}

func NewCachingResponseWriter(w http.ResponseWriter, cw CacheWriter, logctx *apexlog.Logger) CachingResponseWriter {
	return &cachingResponseWriter{
		clientWriter: w,
		cacheWriter:  cw,
		log:          logctx,
	}
}

// Helper functions

func normalizeEtag(s string) string {
	return strings.TrimLeft(s, "W/")
}

type CacheControlDirectives struct {
	NoCache              bool
	NoStore              bool
	MaxAge               *int64
	SMaxAge              *int64
	Private              bool
	staleIfError         *int64
	staleWhileRevalidate *int64
	vary                 []string
}

func (ccd CacheControlDirectives) DoNotCache() bool {
	return ccd.NoCache || ccd.Private || ccd.NoStore || (ccd.SMaxAge != nil && *ccd.SMaxAge == 0) || (ccd.MaxAge != nil && *ccd.MaxAge == 0)
}

func (ccd CacheControlDirectives) CanStaleIfError(age int64) bool {
	return ccd.staleIfError != nil && *ccd.staleIfError > age
}

func (ccd CacheControlDirectives) CanStaleWhileRevalidate(age int64) bool {
	return ccd.staleWhileRevalidate != nil && *ccd.staleWhileRevalidate > age
}

func (ccd CacheControlDirectives) VaryByOrigin() bool {
	for _, v := range ccd.vary {
		if v == "origin" {
			return true
		}
	}

	return false
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
				case "stale-if-error":
					staleIfError, err := strconv.Atoi(v)
					if err == nil {
						staleIfError := int64(staleIfError)
						dirs.staleIfError = &staleIfError
					}
				case "stale-while-revalidate":
					staleWhileRevalidate, err := strconv.Atoi(v)
					if err == nil {
						staleWhileRevalidate := int64(staleWhileRevalidate)
						dirs.staleWhileRevalidate = &staleWhileRevalidate
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
	dirs.vary = allHeaderValues("vary", h)

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

	i, err := strconv.Atoi(splat[1])
	if err != nil || i < 0 {
		return ""
	}

	return splat[1]
}

func IsCacheableError(statusCode int) bool {
	return statusCode >= 400 && statusCode <= 404
}
