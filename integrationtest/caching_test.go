// +build integration

package integrationtest

import (
	"context"
	"fmt"
	apexlog "github.com/apex/log"
	"github.com/c2h5oh/datasize"
	"github.com/richiefi/rrrouter/caching"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/richiefi/rrrouter/config"
	"github.com/richiefi/rrrouter/proxy"
	"github.com/richiefi/rrrouter/server"
)

func Benchmark_sorter1(b *testing.B) {
	type item struct {
		name string
		size int64
	}

	items := make(map[int64]item, 0)
	now := time.Now()
	rand.Seed(now.Unix())

	for i := 0; i < 1000000; i++ {
		anItem := item{size: rand.Int63n(1024 * 1024 * 50), name: uuid.NewV4().String()[:10]}
		accessTime := now.Unix() - rand.Int63n(60*60*24)
		items[accessTime] = anItem
	}

	sortItems := func(items map[int64]item) {
		keys := make([]int64, len(items))
		i := 0
		for at := range items {
			keys[i] = at
			i++
		}
		sort.Slice(keys, func(i int, j int) bool { return keys[i] < keys[j] })
	}

	for i := 0; i < b.N; i++ {
		sortItems(items)
	}
}

func TestServer_client_gets_and_proxy_rule_matches_and_cache_get_is_called(t *testing.T) {
	sh := setup(t)
	conf := testConfig()
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	var written []byte
	getCalled := 0
	tc := NewTestCacheGet("disk1", func(s string, keys []caching.Key, w http.ResponseWriter, l *apexlog.Logger) (caching.CacheResult, caching.Key, error) {
		getCalled += 1
		sw := NewTestStorageWriter(
			func(p []byte) (n int, err error) {
				written = p
				return 0, nil
			}, func() error {
				return nil
			}, func(s int, h http.Header) {
			}, func() (*os.File, error) {
				f := tempFile(t, written)
				return f, nil
			}, func(u *url.URL) {})
		cw, _ := sw.(caching.CacheWriter)
		require.NotNil(t, cw)
		writer := caching.NewCachingResponseWriter(w, cw, l)

		return caching.CacheResult{caching.NotFoundWriter, nil, writer, nil, caching.CacheMetadata{Header: nil, Status: 200}, 0, caching.Stale{IsStale: false}}, keys[0], nil
	})

	listener := listenerWithCache(tc, rules, sh.Logger, conf)
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	require.Equal(t, 1, getCalled)
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 200, resp.StatusCode)
}

func TestCache_query_is_included_in_key(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{"foo": {"bar"}}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Minute * 1)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{"foo": {"bar2"}}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{"foo": {"bar"}}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{"foo": {"bar2"}}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
}

func TestCache_method_is_part_of_cache_key(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.headURLQuery("/t/asdf", listener.URL, url.Values{"Accept-Encoding": {"gzip, deflate"}}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte(""), body)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Minute * 1)
	resp = sh.headURLQuery("/t/asdf", listener.URL, url.Values{"Accept-Encoding": {"gzip, deflate"}}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte(""), body)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{"Accept-Encoding": {"gzip, deflate"}}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Minute * 1)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{"Accept-Encoding": {"gzip, deflate"}}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
}

func tempFile(t *testing.T, b []byte) *os.File {
	fd, err := ioutil.TempFile(t.TempDir(), "caching")
	if err != nil {
		panic(err)
	}
	n, err := fd.Write(b)
	if n != len(b) {
		panic("Wrong len")
	}
	_ = fd.Sync()
	return fd
}

func TestCache_client_gets_twice_and_cache_is_written_to_only_once(t *testing.T) {
	sh := setup(t)
	conf := testConfig()
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	getCalled := 0
	var written []byte
	writeCalled := false
	closeCalled := false
	writeHeaderCalled := false

	tc := NewTestCache("disk1", func(s string, keys []caching.Key, w http.ResponseWriter, l *apexlog.Logger) (caching.CacheResult, caching.Key, error) {
		getCalled += 1
		if getCalled == 2 {
			f := tempFile(t, []byte("ab"))
			return caching.CacheResult{caching.Found, f, nil, nil, caching.CacheMetadata{Header: nil, Status: 200}, 0, caching.Stale{IsStale: false}}, keys[0], nil
		}

		sw := NewTestStorageWriter(
			func(p []byte) (n int, err error) {
				writeCalled = true
				written = p
				return 0, nil
			}, func() error {
				closeCalled = true
				return nil
			}, func(s int, h http.Header) {
				writeHeaderCalled = true
			}, func() (*os.File, error) {
				f := tempFile(t, written)
				return f, nil
			}, func(url *url.URL) {})
		cw, _ := sw.(caching.CacheWriter)
		writer := caching.NewCachingResponseWriter(w, cw, l)

		return caching.CacheResult{caching.NotFoundWriter, nil, writer, nil, caching.CacheMetadata{Header: nil, Status: 200}, 0, caching.Stale{IsStale: false}}, keys[0], nil
	})

	listener := listenerWithCache(tc, rules, sh.Logger, conf)
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	require.Equal(t, getCalled, 1)
	require.True(t, writeHeaderCalled)
	require.True(t, writeCalled)
	require.True(t, closeCalled)
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))

	writeCalled = false
	closeCalled = false
	writeHeaderCalled = false

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	require.Equal(t, getCalled, 2)
	require.False(t, writeHeaderCalled)
	require.False(t, writeCalled)
	require.False(t, closeCalled)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
}

var now time.Time
var hdrs map[string]string

func TestCache_item_cached_then_expires_and_revalidated(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0

	hdrs = map[string]string{"expires": now.Format(time.RFC1123)}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "0", resp.Header.Get("age"))
	require.Equal(t, 1, timesOriginHit)

	now = now.Add(time.Minute * 1)
	hdrs = map[string]string{"expires": now.Add(time.Minute * 1).Format(time.RFC1123)}

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "revalidated", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "0", resp.Header.Get("age"))
	require.Equal(t, 2, timesOriginHit)

	now = now.Add(time.Second * 2)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	age, _ := strconv.Atoi(resp.Header.Get("age"))
	require.Greater(t, age, 1)
	require.Equal(t, 2, timesOriginHit)
}

func TestCache_revalidation_passed_with_etag_given(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0

	hdrs = map[string]string{"expires": now.Format(time.RFC1123), "etag": "\"abcd\""}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "0", resp.Header.Get("age"))
	require.Equal(t, 1, timesOriginHit)

	now = now.Add(time.Minute * 1)
	hdrs = map[string]string{"expires": now.Add(time.Minute * 1).Format(time.RFC1123)}

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"if-none-match": []string{"\"abcd\""}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "revalidated", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "0", resp.Header.Get("age"))
	require.Equal(t, 2, timesOriginHit)

	now = now.Add(time.Second * 2)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	age, _ := strconv.Atoi(resp.Header.Get("age"))
	require.Greater(t, age, 1)
	require.Equal(t, 2, timesOriginHit)
}

func TestCache_etag_suffix_changes_and_client_receives_forced_http_200_with_body(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0

	hdrs = map[string]string{"etag": `"abcd"`, "cache-control": "public"}
	originBody := []byte("ab")
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		if timesOriginHit >= 2 {
			require.Equal(t, `"abcd"`, r.Header.Get("if-none-match"))
			w.WriteHeader(http.StatusNotModified)
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(originBody)
		}
	}))
	defer originServer.Close()

	rules := rulesWithCacheIdRevalidate(t, "disk1", 0, originServer.URL, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, `"abcd"`, resp.Header.Get("etag"))
	require.Equal(t, 1, timesOriginHit)

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"if-none-match": []string{`"abcd"`}})
	defer resp.Body.Close()
	require.Equal(t, 304, resp.StatusCode)
	body = sh.readBody(resp)
	require.Equal(t, []byte(""), body)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, `"abcd"`, resp.Header.Get("etag"))
	require.Equal(t, 1, timesOriginHit)

	token := "-001"
	prevToken := os.Getenv("ETAG_SUFFIX")
	os.Setenv("ETAG_SUFFIX", token)

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"if-none-match": []string{`"abcd"`}})
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, `"abcd`+token+`"`, resp.Header.Get("etag"))
	require.Equal(t, 1, timesOriginHit)

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"if-none-match": []string{`"abcd` + token + `"`}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 304, resp.StatusCode)
	require.Equal(t, []byte(""), body)
	require.Equal(t, `"abcd`+token+`"`, resp.Header.Get("etag"))
	require.Equal(t, 1, timesOriginHit)

	os.Setenv("ETAG_SUFFIX", prevToken)
}

func TestCache_item_revalidation_uses_conditionals_if_available(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0

	hdrs = map[string]string{"expires": now.Format(time.RFC1123), "etag": "\"abcd\""}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		if timesOriginHit == 2 {
			require.Equal(t, "\"abcd\"", r.Header.Get("if-none-match"))
			w.WriteHeader(http.StatusNotModified)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "0", resp.Header.Get("age"))
	require.Equal(t, "\"abcd"+ETagToken()+"\"", resp.Header.Get("etag"))

	now = now.Add(time.Minute * 1)
	hdrs = map[string]string{"expires": now.Add(time.Minute * 1).Format(time.RFC1123)}

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, "revalidated", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "0", resp.Header.Get("age"))

	now = now.Add(time.Second * 2)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	age, _ := strconv.Atoi(resp.Header.Get("age"))
	require.Greater(t, age, 1)
}

func TestCache_forced_revalidate_interval(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0

	hdrs = map[string]string{"expires": now.Add(time.Minute * 1).Format(time.RFC1123)}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheIdRevalidate(t, "disk1", 10, originServer.URL, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 1, timesOriginHit)

	now = now.Add(time.Second * 15)
	hdrs = map[string]string{"expires": now.Add(time.Minute * 1).Format(time.RFC1123)}

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "revalidated", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 2, timesOriginHit)

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 2, timesOriginHit)
}

func TestCache_lying_origin_etags_and_revalidate(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0

	hdrs = map[string]string{"expires": now.Add(time.Minute * 1).Format(time.RFC1123), "etag": "1", "cache-control": "public", "vary": "origin"}
	originBody := []byte("ab")
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(originBody)
	}))
	defer originServer.Close()

	rules := rulesWithCacheIdRevalidate(t, "disk1", 10, originServer.URL, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "1"+ETagToken(), resp.Header.Get("etag"))
	require.Equal(t, 1, timesOriginHit)

	now = now.Add(time.Second * 10)
	hdrs = map[string]string{"expires": now.Add(time.Minute * 1).Format(time.RFC1123), "etag": "1", "cache-control": "public", "vary": "origin"}
	originBody = []byte("AB")

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"if-none-match": []string{"1" + ETagToken()}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, []byte("AB"), body)
	require.Equal(t, "revalidated", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "1"+ETagToken(), resp.Header.Get("etag"))
	require.Equal(t, 2, timesOriginHit)

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("AB"), body)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "1"+ETagToken(), resp.Header.Get("etag"))
	require.Equal(t, 2, timesOriginHit)

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"if-none-match": []string{"1" + ETagToken()}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 304, resp.StatusCode)
	require.Equal(t, []byte(""), body)
	require.Equal(t, "1"+ETagToken(), resp.Header.Get("etag"))
	require.Equal(t, "origin", resp.Header.Get("vary"))
	require.Equal(t, "public", resp.Header.Get("cache-control"))
	require.Equal(t, now.Add(time.Minute*1).Format(time.RFC1123), resp.Header.Get("expires"))
	require.Equal(t, 2, timesOriginHit)
}

func TestCache_304_from_origin_updates_headers_in_cache(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0

	hdrs = map[string]string{}
	status := 200
	originBody := []byte("ab")

	port := rand.Intn(30000) + 20000
	originListener, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	require.NoError(t, err)
	var tcpListener = func() {
		for {
			conn, err := originListener.Accept()
			if err != nil {
				continue
			}
			timesOriginHit += 1
			_, err = conn.Write([]byte(fmt.Sprintf("HTTP/1.1 %d OK\r\n", status)))
			require.NoError(t, err)
			for k, v := range hdrs {
				_, err = conn.Write([]byte(fmt.Sprintf("%s: %s\r\n", k, v)))
				require.NoError(t, err)
			}
			_, err = conn.Write([]byte("\r\n"))
			require.NoError(t, err)
			if status == 200 {
				_, err = conn.Write(originBody)
				require.NoError(t, err)
			}
			_ = conn.Close()
		}
	}
	go tcpListener()

	rules := rulesWithCacheIdRevalidate(t, "disk1", 10, "http://127.0.0.1:"+strconv.Itoa(port), sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	hdrs = map[string]string{"etag": "1", "cache-control": "public, max-age=60", "content-encoding": "application/json", "content-length": "2"}
	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "1", resp.Header.Get("etag"))
	require.Equal(t, "application/json", resp.Header.Get("content-encoding"))
	require.Equal(t, "2", resp.Header.Get("content-length"))
	require.Equal(t, 1, timesOriginHit)

	now = now.Add(time.Second * 120)

	hdrs["cache-control"] = "public, max-age=120"
	hdrs["content-location"] = "puppa"
	hdrs["date"] = "puppa"
	hdrs["last-modified"] = "puppa"
	hdrs["expires"] = "puppa"
	hdrs["vary"] = "puppa"
	hdrs["not-allowed-in-304"] = "puppa"
	hdrs["content-length"] = "0"
	delete(hdrs, "content-encoding")
	status = 304

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"if-none-match": []string{"1"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 304, resp.StatusCode)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "1", resp.Header.Get("etag"))
	require.Equal(t, "public, max-age=120", resp.Header.Get("cache-control"))
	require.Equal(t, "puppa", resp.Header.Get("content-location"))
	require.Equal(t, "puppa", resp.Header.Get("date"))
	require.Equal(t, "puppa", resp.Header.Get("last-modified"))
	require.Equal(t, "puppa", resp.Header.Get("expires"))
	require.Equal(t, "puppa", resp.Header.Get("vary"))
	require.Equal(t, "", resp.Header.Get("content-encoding"))
	require.Equal(t, "", resp.Header.Get("not-allowed-in-304"))
	require.Equal(t, 2, timesOriginHit)

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "1", resp.Header.Get("etag"))
	require.Equal(t, "public, max-age=120", resp.Header.Get("cache-control"))
	require.Equal(t, "puppa", resp.Header.Get("content-location"))
	require.Equal(t, "puppa", resp.Header.Get("date"))
	require.Equal(t, "puppa", resp.Header.Get("last-modified"))
	require.Equal(t, "puppa", resp.Header.Get("expires"))
	require.Equal(t, "puppa", resp.Header.Get("vary"))
	require.Equal(t, "application/json", resp.Header.Get("content-encoding"))
	require.Equal(t, "2", resp.Header.Get("content-length"))
	require.Equal(t, 2, timesOriginHit)

}

func TestCache_origin_keyed_by_existence_rather_than_value_if_vary_origin_not_in_origin_response(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0

	hdrs = map[string]string{"expires": now.Add(time.Minute * 1).Format(time.RFC1123)}
	originBody := []byte("ab")
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(originBody)
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	reqhdrs := http.Header{"origin": []string{"https://example.com/A"}}
	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, reqhdrs)
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 1, timesOriginHit)

	reqhdrs = http.Header{"origin": []string{"https://example.com/B"}}
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, reqhdrs)
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 1, timesOriginHit)

	reqhdrs = http.Header{}
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, reqhdrs)
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 2, timesOriginHit)
}

func TestCache_origin_keyed_by_origin_value_if_vary_origin_in_origin_response(t *testing.T) {

	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0

	hdrs = map[string]string{"expires": now.Add(time.Minute * 1).Format(time.RFC1123), "vary": "origin"}
	originBody := []byte("ab")
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(originBody)
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	reqhdrs := http.Header{"origin": []string{"https://example.com/A"}}
	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, reqhdrs)
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "origin", resp.Header.Get("vary"))
	require.Equal(t, 1, timesOriginHit)

	reqhdrs = http.Header{"origin": []string{"https://example.com/A"}}
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, reqhdrs)
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "origin", resp.Header.Get("vary"))
	require.Equal(t, 1, timesOriginHit)

	reqhdrs = http.Header{"origin": []string{"https://example.com/B"}}
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, reqhdrs)
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "origin", resp.Header.Get("vary"))
	require.Equal(t, 2, timesOriginHit)

	reqhdrs = http.Header{}
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, reqhdrs)
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "origin", resp.Header.Get("vary"))
	require.Equal(t, 3, timesOriginHit)
}

func TestCache_item_cached_then_cache_control_max_age_passed(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0

	hdrs = map[string]string{"cache-control": "max-age=60, something"}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	//closeChan := make(chan bool, 3)
	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 1, timesOriginHit)
	//require.Equal(t, true, <-closeChan)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Second * 70)

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	//require.Equal(t, true, <-closeChan)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, "revalidated", resp.Header.Get("richie-edge-cache"))

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
}

func TestCache_item_cached_then_cache_control_smax_age_passed(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	hdrs = map[string]string{"cache-control": "s-maxage=60, max-age=10"}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Second * 70)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, "revalidated", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Second * 30)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
}

func TestCache_cache_control_caching_not_allowed(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	hdrs = map[string]string{"cache-control": "private"}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "uncacheable", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Minute * 1)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, "uncacheable", resp.Header.Get("richie-edge-cache"))

	hdrs = map[string]string{"cache-control": "no-cache"}
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 3, timesOriginHit)
	require.Equal(t, "uncacheable", resp.Header.Get("richie-edge-cache"))

	hdrs = map[string]string{"cache-control": "s-maxage=0"}
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 4, timesOriginHit)
	require.Equal(t, "uncacheable", resp.Header.Get("richie-edge-cache"))

	hdrs = map[string]string{"cache-control": "max-age=0"}
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 5, timesOriginHit)
	require.Equal(t, "uncacheable", resp.Header.Get("richie-edge-cache"))

	hdrs = map[string]string{"cache-control": "no-store"}
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 6, timesOriginHit)
	require.Equal(t, "uncacheable", resp.Header.Get("richie-edge-cache"))
}

func TestCache_stale_if_error_used(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	originStatus := 0
	hdrs = map[string]string{"cache-control": "s-maxage=60, max-age=60, stale-if-error=600"}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		if timesOriginHit == 2 {
			originStatus = 500
			w.WriteHeader(originStatus)
			return
		}
		originStatus = 200
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		w.WriteHeader(originStatus)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 1, timesOriginHit)
	age, err := strconv.Atoi(resp.Header.Get("age"))
	require.Nil(t, err)
	require.True(t, age >= 0 && age <= 1)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Minute * 2)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, 500, originStatus)
	require.Equal(t, []byte("ab"), body)
	age, err = strconv.Atoi(resp.Header.Get("age"))
	require.Nil(t, err)
	require.True(t, age >= 110 && age <= 130)
	require.Equal(t, "stale", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Second * 30)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 3, timesOriginHit)
	require.Equal(t, "revalidated", resp.Header.Get("richie-edge-cache"))
}

func TestCache_stale_if_error_readers_get_stale(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	originStatus := 0
	hdrs = map[string]string{"cache-control": "s-maxage=60, max-age=60, stale-if-error=600"}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		if timesOriginHit >= 2 {
			time.Sleep(time.Millisecond * 200)
			originStatus = 500
			w.WriteHeader(originStatus)
			return
		}
		originStatus = 200
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		w.WriteHeader(originStatus)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 1, timesOriginHit)
	age, err := strconv.Atoi(resp.Header.Get("age"))
	require.Nil(t, err)
	require.True(t, age >= 0 && age <= 1)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Minute * 2)
	wg := sync.WaitGroup{}
	edgeCacheStatusesChan := make(chan string, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
			defer resp.Body.Close()
			body := sh.readBody(resp)
			require.Equal(t, []byte("ab"), body)
			age, err = strconv.Atoi(resp.Header.Get("age"))
			require.True(t, age >= 120 && age <= 121)
			edgeCacheStatusesChan <- resp.Header.Get("richie-edge-cache")
			wg.Done()
		}()
		if i == 0 {
			time.Sleep(time.Millisecond * 100)
		}
	}
	wg.Wait()
	stale := 0
	for i := 0; i < 3; i++ {
		s := <-edgeCacheStatusesChan
		if s == "stale" {
			stale += 1
		}
	}
	require.Equal(t, 3, stale)
	require.Equal(t, 2, timesOriginHit)
}

func TestCache_stale_while_revalidate_serves_readers_with_stale_while_writer_revalidates(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	hdrs = map[string]string{"cache-control": "s-maxage=60, max-age=60, stale-while-revalidate=600"}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		if timesOriginHit >= 2 {
			time.Sleep(time.Millisecond * 200)
		}
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 1, timesOriginHit)
	age, err := strconv.Atoi(resp.Header.Get("age"))
	require.Nil(t, err)
	require.True(t, age >= 0 && age <= 1)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Minute * 2)
	wg := sync.WaitGroup{}
	edgeCacheStatusesChan := make(chan string, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
			defer resp.Body.Close()
			body := sh.readBody(resp)
			require.Equal(t, []byte("ab"), body)
			age, err = strconv.Atoi(resp.Header.Get("age"))
			edgeCacheStatus := resp.Header.Get("richie-edge-cache")
			if edgeCacheStatus == "revalidated" {
				require.Equal(t, 0, age)
			} else {
				require.True(t, age >= 120 && age <= 121)
			}
			edgeCacheStatusesChan <- edgeCacheStatus
			wg.Done()
		}()
		if i == 0 {
			time.Sleep(time.Millisecond * 100)
		} else {
			time.Sleep(time.Millisecond * 5)
		}
	}
	wg.Wait()
	revalidated := 0
	stale := 0
	for i := 0; i < 3; i++ {
		s := <-edgeCacheStatusesChan
		if s == "stale" {
			stale += 1
		} else if s == "revalidated" {
			revalidated += 1
		}
	}
	require.Equal(t, 1, revalidated)
	require.Equal(t, 2, stale)
	require.Equal(t, 2, timesOriginHit)
}

func TestCache_cache_control_no_store_not_cached(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	hdrs = map[string]string{"cache-control": "no-store"}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "uncacheable", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Minute * 1)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, "uncacheable", resp.Header.Get("richie-edge-cache"))
}

func TestCache_cache_control_max_age_0_not_cached(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	hdrs = map[string]string{"cache-control": "max-age=0"}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "uncacheable", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Minute * 1)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, "uncacheable", resp.Header.Get("richie-edge-cache"))
}

func TestCache_request_with_authorization_header_skipped(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	hdrs = map[string]string{}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"authorization": {"Bearer abc"}})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "pass", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Minute * 1)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"authorization": {"Bearer abc"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, "pass", resp.Header.Get("richie-edge-cache"))
}

func TestCache_request_with_authorization_header_not_cached_but_subrequest_is_cached(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	timesRedirectHit := 0
	redirectReceivedAuthorization := false
	hdrs = map[string]string{}
	redirectTargetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesRedirectHit += 1
		redirectReceivedAuthorization = len(r.Header.Get("authorization")) > 0
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer redirectTargetServer.Close()
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		h.Set("Location", redirectTargetServer.URL+"/redir")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer originServer.Close()

	reqHdrs := make(map[string]interface{})
	reqHdrs["authorization"] = nil
	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:              "/t/*",
			Destination:       fmt.Sprintf("%s/$1", originServer.URL),
			CacheId:           "disk1",
			RestartOnRedirect: true,
		},
		{
			Path:           "/redir",
			Destination:    fmt.Sprintf("%s", redirectTargetServer.URL+"/redir"),
			CacheId:        "disk1",
			RequestHeaders: reqHdrs,
		},
	}, sh.Logger)
	if err != nil || rules == nil {
		t.Fatal("Bad rules")
	}

	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"authorization": {"Bearer abc"}})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, 1, timesRedirectHit)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))

	require.Equal(t, false, redirectReceivedAuthorization)

	now = now.Add(time.Minute * 2)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"authorization": {"Bearer 123"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, 1, timesRedirectHit)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	age, err := strconv.Atoi(resp.Header.Get("age"))
	require.Nil(t, err)
	require.True(t, age >= 60)
}

func TestCache_4xx_is_cached_for_a_fixed_time(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0

	hdrs = map[string]string{"cache-control": "max-age=600"}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		if timesOriginHit < 2 {
			w.WriteHeader(404)
		} else {
			w.WriteHeader(403)
		}
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, 404, resp.StatusCode)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Second * 30)

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 404, resp.StatusCode)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Second * 31) // Fixed time being 60s

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 403, resp.StatusCode)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, "revalidated", resp.Header.Get("richie-edge-cache"))
}

func TestCache_request_with_range_is_omitted_to_origin_and_client_range_served_from_cache(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	hdrs = map[string]string{}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "", r.Header.Get("range"))
		timesOriginHit += 1
		w.Header().Add("cache-control", "max-age=86400")
		w.Header().Add("accept-ranges", "bytes")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("abAB"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"range": {"bytes=0-1"}, "accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 206, resp.StatusCode)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "2", resp.Header.Get("content-length"))
	require.Equal(t, "bytes 0-1/4", resp.Header.Get("content-range"))

	now = now.Add(time.Minute * 1)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"range": {"bytes=2-3"}, "accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 206, resp.StatusCode)
	require.Equal(t, []byte("AB"), body)
	require.Equal(t, "2", resp.Header.Get("content-length"))
	require.Equal(t, "bytes 2-3/4", resp.Header.Get("content-range"))

	now = now.Add(time.Minute * 1)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, []byte("abAB"), body)
	require.Equal(t, "4", resp.Header.Get("content-length"))
	require.Equal(t, "", resp.Header.Get("content-range"))

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"range": {"bytes=0-0"}, "accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 206, resp.StatusCode)
	require.Equal(t, []byte("a"), body)
	require.Equal(t, "1", resp.Header.Get("content-length"))
	require.Equal(t, "bytes 0-0/4", resp.Header.Get("content-range"))

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"range": {"bytes=0-"}, "accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 206, resp.StatusCode)
	require.Equal(t, []byte("abAB"), body)
	require.Equal(t, "4", resp.Header.Get("content-length"))
	require.Equal(t, "bytes 0-3/4", resp.Header.Get("content-range"))

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"range": {"bytes=-2"}, "accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 206, resp.StatusCode)
	require.Equal(t, []byte("AB"), body)
	require.Equal(t, "2", resp.Header.Get("content-length"))
	require.Equal(t, "bytes 2-3/4", resp.Header.Get("content-range"))

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"range": {"bytes=-1"}, "accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 206, resp.StatusCode)
	require.Equal(t, []byte("B"), body)
	require.Equal(t, "1", resp.Header.Get("content-length"))
	require.Equal(t, "bytes 3-3/4", resp.Header.Get("content-range"))

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"range": {"bytes=-"}, "accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 1, timesOriginHit)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, []byte("abAB"), body)
	require.Equal(t, "4", resp.Header.Get("content-length"))
	require.Equal(t, "", resp.Header.Get("content-range"))
}

func TestCache_redirection_steps_cached_individually(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	hdrs = map[string]string{}
	var listener *httptest.Server
	var originServerBaseURL string
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		var status int
		location := ""
		if r.RequestURI == "/asdf" {
			status = 302
			location = "/t/redir/subpath1"
		} else if r.RequestURI == "/t/redir/subpath1" {
			status = 302
			location = "/t/redir/subpath2"
		} else if r.RequestURI == "/t/redir/subpath2" {
			status = 200
		}
		w.Header().Add("cache-control", "max-age=86400")
		if status != 200 {
			w.Header().Set("location", originServerBaseURL+location)
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()
	originServerBaseURL = originServer.URL

	queriedKeys := []caching.Key{}
	storages := []*caching.Storage{}
	storageDir := t.TempDir()
	ts := newTestStorage(caching.NewDiskStorage("disk1", storageDir, int64(datasize.MB*1), sh.Logger, func() time.Time { return now }), func(key caching.Key) {
		queriedKeys = append(queriedKeys, key)
	})
	storages = append(storages, &ts)

	rules := rulesWithCacheIdRestartOnRedirect(t, "disk1", true, originServer, sh)
	c := caching.NewCacheWithStorages(storages, sh.Logger, func() time.Time {
		return now
	})

	listener = listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 3, timesOriginHit)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 3, len(queriedKeys))

	time.Sleep(time.Millisecond * 100)

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 3, timesOriginHit)
	require.Equal(t, []byte("ab"), body)

	for _, k := range queriedKeys {
		_, err := os.Stat(filepath.Join(storageDir, k.FsName()))
		require.Nil(t, err)
	}
	p := filepath.Join(storageDir, queriedKeys[4].FsName()) // Key at index 4 is /t/redir/subpath1
	err := os.Remove(p)
	require.Nil(t, err)
	require.Equal(t, 6, len(queriedKeys))

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 4, timesOriginHit)
	require.Equal(t, []byte("ab"), body)

	require.Equal(t, 9, len(queriedKeys))
}

func TestCache_redirection_steps_cached_individually_with_recompression(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	hdrs = map[string]string{}
	var listener *httptest.Server
	var originServerBaseURL string
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		var status int
		location := ""
		if r.RequestURI == "/asdf" {
			status = 302
			location = "/t/redir/subpath1"
		} else if r.RequestURI == "/t/redir/subpath1" {
			status = 302
			location = "/t/redir/subpath2"
		} else if r.RequestURI == "/t/redir/subpath2" {
			status = 200
		}
		w.Header().Add("cache-control", "max-age=86400")
		if status != 200 {
			w.Header().Set("location", originServerBaseURL+location)
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(plainBody))
	}))
	defer originServer.Close()
	originServerBaseURL = originServer.URL

	queriedKeys := []caching.Key{}
	storages := []*caching.Storage{}
	storageDir := t.TempDir()
	ts := newTestStorage(caching.NewDiskStorage("disk1", storageDir, int64(datasize.MB*1), sh.Logger, func() time.Time { return now }), func(key caching.Key) {
		queriedKeys = append(queriedKeys, key)
	})
	storages = append(storages, &ts)

	rules := rulesWithCacheIdRestartOnRedirectRecompression(t, "disk1", true, true, originServer, sh)
	c := caching.NewCacheWithStorages(storages, sh.Logger, func() time.Time {
		return now
	})

	listener = listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 3, timesOriginHit)
	require.Equal(t, []byte(gzBody), body)

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 3, timesOriginHit)
	require.Equal(t, []byte(gzBody), body)

	for _, k := range queriedKeys {
		_, err := os.Stat(filepath.Join(storageDir, k.FsName()))
		require.Nil(t, err)
	}
	p := filepath.Join(storageDir, queriedKeys[4].FsName()) // Key at index 4 is /t/redir/subpath1
	err := os.Remove(p)
	require.Nil(t, err)
	require.Equal(t, 6, len(queriedKeys))

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 4, timesOriginHit)
	require.Equal(t, []byte(gzBody), body)

	require.Equal(t, 9, len(queriedKeys))
}

func TestCache_redirection_subrequests_inherit_parent_request_rules_if_no_match(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	hdrs = map[string]string{}
	var listener *httptest.Server
	var originServerBaseURL string
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		var status int
		location := ""
		if r.RequestURI == "/asdf" {
			status = 302
			location = "/t/redir/subpath1"
		} else if r.RequestURI == "/t/redir/subpath1" {
			status = 302
			location = "/nomatch/subpath2"
		} else {
			u, _ := url.Parse(originServerBaseURL)
			require.Equal(t, u.Host, r.Host)
			status = 200
		}
		w.Header().Add("cache-control", "max-age=86400")
		if status != 200 {
			w.Header().Set("location", originServerBaseURL+location)
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("ab"))
	}))
	defer originServer.Close()
	originServerBaseURL = originServer.URL

	storages := []*caching.Storage{}
	storageDir := t.TempDir()
	ts := newTestStorage(caching.NewDiskStorage("disk1", storageDir, int64(datasize.MB*1), sh.Logger, func() time.Time { return now }), func(key caching.Key) {})
	storages = append(storages, &ts)

	rules := rulesWithCacheIdRestartOnRedirectResponseHeaders(t, "disk1", true, map[string]string{"timing-allow-origin": "*"}, originServer, sh)
	c := caching.NewCacheWithStorages(storages, sh.Logger, func() time.Time {
		return now
	})

	listener, router := listenerAndRouterWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 3, timesOriginHit)
	require.Equal(t, "*", resp.Header.Get("timing-allow-origin"))
	require.Equal(t, []byte("ab"), body)

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:              "/t/*",
			Destination:       fmt.Sprintf("%s/$1", originServer.URL),
			Internal:          false,
			Recompression:     true,
			CacheId:           "disk1",
			RestartOnRedirect: true,
			ResponseHeaders:   map[string]string{"timing-allow-origin": "something-else"},
		},
	}, sh.Logger)
	if err != nil || rules == nil {
		t.Fatal("Bad rules")
	}
	router.SetRules(rules)

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 3, timesOriginHit)
	require.Equal(t, "something-else", resp.Header.Get("timing-allow-origin"))
	require.Equal(t, []byte("ab"), body)
}

func TestCache_recursive_redirects_not_allowed(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	hdrs = map[string]string{}
	var listener *httptest.Server
	var originServerBaseURL string
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		status := 0
		location := ""
		if timesOriginHit == 1 {
			status = 302
			location = "/t/redir/subpath1"
		} else if timesOriginHit == 2 {
			status = 307
			location = "/t/redir/subpath1"
		}
		w.Header().Set("location", originServerBaseURL+location)
		w.WriteHeader(status)
	}))
	defer originServer.Close()
	originServerBaseURL = originServer.URL

	storages := []*caching.Storage{}
	storageDir := t.TempDir()
	ts := newTestStorage(caching.NewDiskStorage("disk1", storageDir, int64(datasize.MB*1), sh.Logger, func() time.Time { return now }), func(key caching.Key) {})
	storages = append(storages, &ts)

	rules := rulesWithCacheIdRestartOnRedirectResponseHeaders(t, "disk1", true, map[string]string{"timing-allow-origin": "*"}, originServer, sh)
	c := caching.NewCacheWithStorages(storages, sh.Logger, func() time.Time {
		return now
	})

	listener = listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	require.Equal(t, 508, resp.StatusCode)
	require.Equal(t, 2, timesOriginHit)
}

func TestCache_restart_on_redirect_relative_redirects_use_destination_host(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	var listener *httptest.Server
	var originServerBaseURL string
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		status := 0
		if timesOriginHit == 1 {
			status = 302
			w.Header().Set("location", "/t/redir/subpath1")
		} else if timesOriginHit == 2 {
			status = 200
		}
		w.WriteHeader(status)
	}))
	defer originServer.Close()
	originServerBaseURL = originServer.URL

	setRedirectedURLString := ""
	written := []byte{}
	rules := rulesWithCacheIdRestartOnRedirectResponseHeaders(t, "disk1", true, map[string]string{"timing-allow-origin": "*"}, originServer, sh)
	tc := NewTestCacheGet("disk1", func(s string, keys []caching.Key, w http.ResponseWriter, l *apexlog.Logger) (caching.CacheResult, caching.Key, error) {
		sw := NewTestStorageWriter(
			func(p []byte) (n int, err error) {
				return 0, nil
			}, func() error {
				return nil
			}, func(s int, h http.Header) {
			}, func() (*os.File, error) {
				f := tempFile(t, written)
				return f, nil
			}, func(u *url.URL) {
				setRedirectedURLString = u.String()
			})
		cw, _ := sw.(caching.CacheWriter)
		require.NotNil(t, cw)
		writer := caching.NewCachingResponseWriter(w, cw, l)
		return caching.CacheResult{caching.NotFoundWriter, nil, writer, nil, caching.CacheMetadata{Header: nil, Status: 200}, 0, caching.Stale{IsStale: false}}, keys[0], nil
	})

	listener = listenerWithCache(tc, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	require.True(t, len(originServerBaseURL) > 0)
	require.Equal(t, originServerBaseURL+"/t/redir/subpath1", setRedirectedURLString)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, 2, timesOriginHit)
}

func TestCache_one_writer_two_readers(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	hdrs = map[string]string{}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		time.Sleep(time.Millisecond * 100)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	wg := sync.WaitGroup{}
	edgeCacheStatusesChan := make(chan string, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
			defer resp.Body.Close()
			body := sh.readBody(resp)
			require.Equal(t, []byte("ab"), body)
			edgeCacheStatusesChan <- resp.Header.Get("richie-edge-cache")
			wg.Done()
		}()
	}
	wg.Wait()
	miss := 0
	hit := 0
	for i := 0; i < 3; i++ {
		s := <-edgeCacheStatusesChan
		if s == "hit" {
			hit += 1
		} else if s == "miss" {
			miss += 1
		}
	}
	require.Equal(t, 1, miss)
	require.Equal(t, 2, hit)
	require.Equal(t, 1, timesOriginHit)
}

func TestCache_writer_times_out_and_one_reader_becomes_writer(t *testing.T) {

	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	hdrs = map[string]string{}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		if timesOriginHit == 1 {
			time.Sleep(time.Second * 1) // Wait with the writer and let the client time out in the meantime
		}
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	wg := sync.WaitGroup{}
	edgeCacheStatusesChan := make(chan string, 3)
	wg.Add(3)
	for i := 0; i < 3; i++ {
		go func(n int) {
			to := 1500
			if n == 0 {
				to = 500
			} else {
				time.Sleep(time.Millisecond * 200)
			}
			resp := sh.URLQueryWithBodyTimeout("GET", "/t/asdf", listener.URL, url.Values{}, http.Header{}, nil, to)
			if resp == nil {
				edgeCacheStatusesChan <- "timeout"
				wg.Done()
				return
			}
			defer resp.Body.Close()
			body := sh.readBody(resp)
			require.Equal(t, []byte("ab"), body)
			edgeCacheStatusesChan <- resp.Header.Get("richie-edge-cache")
			wg.Done()
		}(i)
	}
	wg.Wait()

	miss := 0
	hit := 0
	timeout := 0
	for i := 0; i < 3; i++ {
		s := <-edgeCacheStatusesChan
		if s == "hit" {
			hit += 1
		} else if s == "miss" {
			miss += 1
		} else if s == "timeout" {
			timeout += 1
		}
	}
	require.Equal(t, 1, timeout)
	require.Equal(t, 0, miss)
	require.Equal(t, 2, hit)
	require.Equal(t, 1, timesOriginHit)
}

func TestCache_entry_expires_and_is_revalidated_with_multiple_requests_waiting(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	hdrs = map[string]string{}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		time.Sleep(time.Millisecond * 100)
		w.Header().Add("cache-control", "max-age=2")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ab"))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Second * 1)

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))

	require.Equal(t, 1, timesOriginHit)

	now = now.Add(time.Second * 2)

	wg := sync.WaitGroup{}
	edgeCacheStatusesChan := make(chan string, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
			defer resp.Body.Close()
			body := sh.readBody(resp)
			require.Equal(t, []byte("ab"), body)
			edgeCacheStatusesChan <- resp.Header.Get("richie-edge-cache")
			wg.Done()
		}()
	}
	wg.Wait()
	revalidated := 0
	hit := 0
	for i := 0; i < 3; i++ {
		s := <-edgeCacheStatusesChan
		if s == "hit" {
			hit += 1
		} else if s == "revalidated" {
			revalidated += 1
		}
	}
	require.Equal(t, 1, revalidated)
	require.Equal(t, 2, hit)
	require.Equal(t, 2, timesOriginHit)
}

func TestCache_entry_is_revalidated_for_waiting_clients_with_rules_changed(t *testing.T) {
	sh := setup(t)
	now = time.Now()
	timesOriginHit := 0
	hdrs = map[string]string{}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesOriginHit += 1
		h := w.Header()
		for k, v := range hdrs {
			h.Set(k, v)
		}
		time.Sleep(time.Millisecond * 100)
		w.Header().Add("cache-control", "max-age=2")
		w.Header().Set("content-type", "application/json")
		w.Header().Set("content-encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(gzBody))
	}))
	defer originServer.Close()

	rules := rulesWithCacheId(t, "disk1", originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	})

	listener, router := listenerAndRouterWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte(gzBody), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Second * 1)

	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:              "/t/*",
			Destination:       fmt.Sprintf("%s/$1", originServer.URL),
			Internal:          false,
			Recompression:     true,
			CacheId:           "disk1",
			RestartOnRedirect: true,
			ResponseHeaders:   map[string]string{"hello": "ruby"},
		},
	}, sh.Logger)
	if err != nil || rules == nil {
		t.Fatal("Bad rules")
	}
	router.SetRules(rules)

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"accept-encoding": {"gzip"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, []byte(gzBody), body)
	require.Equal(t, "ruby", resp.Header.Get("hello"))
	require.Equal(t, 1, timesOriginHit)

	now = now.Add(time.Second * 2)

	wg := sync.WaitGroup{}
	edgeCacheStatusesChan := make(chan string, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"accept-encoding": {"gzip"}})
			defer resp.Body.Close()
			body := sh.readBody(resp)
			require.Equal(t, []byte(gzBody), body)
			require.Equal(t, "ruby", resp.Header.Get("hello"))
			edgeCacheStatusesChan <- resp.Header.Get("richie-edge-cache")
			wg.Done()
		}()
	}
	wg.Wait()
	revalidated := 0
	hit := 0
	for i := 0; i < 3; i++ {
		s := <-edgeCacheStatusesChan
		if s == "hit" {
			hit += 1
		} else if s == "revalidated" {
			revalidated += 1
		}
	}
	require.Equal(t, 1, revalidated)
	require.Equal(t, 2, hit)
	require.Equal(t, 2, timesOriginHit)
}

type entry struct {
	reader       *os.File
	headerStatus caching.CacheMetadata
	age          int
}

type testCache struct {
	caching.Cache
	cacheId     string
	cachedEntry *entry
	get         func(string, []caching.Key, http.ResponseWriter, *apexlog.Logger) (caching.CacheResult, caching.Key, error)
	getWriter   func(cacheId string, k caching.Key, revalidate bool) caching.CacheWriter
}

func (c *testCache) Get(ctx context.Context, s string, ri int, skipRevalidate bool, keys []caching.Key, w http.ResponseWriter, l *apexlog.Logger) (caching.CacheResult, caching.Key, error) {
	if s != c.cacheId {
		return caching.CacheResult{caching.NotFoundReader, nil, nil, nil, caching.CacheMetadata{Header: http.Header{}, Status: 200}, 0, caching.Stale{IsStale: false}}, keys[0], nil
	}

	if e := c.cachedEntry; e != nil {
		return caching.CacheResult{caching.Found, e.reader, nil, nil, e.headerStatus, int64(e.age), caching.Stale{IsStale: false}}, keys[0], nil
	}

	return c.get(s, keys, w, l)
}

func (c *testCache) Finish(caching.Key, *apexlog.Logger) {

}

func (c *testCache) HasStorage(id string) bool {
	return true
}

func (c *testCache) HealthCheck() error {
	return nil
}

type testStorage struct {
	s           caching.Storage
	queriedKeys func(caching.Key)
}

func (ts *testStorage) GetWriter(k caching.Key, r bool, c *chan caching.KeyInfo) caching.StorageWriter {
	return ts.s.GetWriter(k, r, c)
}

func (ts *testStorage) Get(ctx context.Context, keys []caching.Key) (*os.File, caching.StorageMetadata, caching.Key, error) {
	w, sm, key, err := ts.s.Get(ctx, keys)
	ts.queriedKeys(key)
	return w, sm, key, err
}

func (ts *testStorage) Id() string {
	return ts.s.Id()
}

func (ts *testStorage) Update(cfg caching.StorageConfiguration) {

}

func (ts *testStorage) SetIsReplaced() {

}

func (ts *testStorage) WriteTest() (bool, error) {
	return true, nil
}

func newTestStorage(s caching.Storage, queriedKeys func(caching.Key)) caching.Storage {
	return &testStorage{
		s:           s,
		queriedKeys: queriedKeys,
	}
}

type testStorageWriter struct {
	caching.StorageWriter
	write            func(p []byte) (n int, err error)
	close            func() error
	writeHeader      func(int, http.Header)
	writtenFile      func() (*os.File, error)
	setRedirectedURL func(*url.URL)
}

func (sw testStorageWriter) WriteHeader(s int, h http.Header) {
	sw.writeHeader(s, h)
}

func (sw testStorageWriter) Write(p []byte) (n int, err error) {
	return sw.write(p)
}

func (sw testStorageWriter) Close() error {
	return sw.close()
}

func (sw testStorageWriter) WrittenFile() (*os.File, error) {
	return sw.writtenFile()
}

func (sw testStorageWriter) Flush() {
}

func (sw testStorageWriter) SetRedirectedURL(redir *url.URL) {
	if sw.setRedirectedURL != nil {
		sw.setRedirectedURL(redir)
	}
}

func (sw testStorageWriter) SetRevalidated(h http.Header) {
}

func (sw testStorageWriter) SetRevalidateErrored(canStaleIfError bool) {
}

func (sw testStorageWriter) ChangeKey(caching.Key) error {
	return nil
}

func (sw testStorageWriter) Delete() error {
	return nil
}

func NewTestStorageWriter(write func(p []byte) (n int, err error), close func() error, writeHeader func(int, http.Header), writtenFile func() (*os.File, error), setRedirectedURL func(*url.URL)) caching.StorageWriter {
	return &testStorageWriter{
		write:            write,
		close:            close,
		writeHeader:      writeHeader,
		writtenFile:      writtenFile,
		setRedirectedURL: setRedirectedURL,
	}
}

type testCacheWriter struct {
	caching.CacheWriter
	write       func(p []byte) (n int, err error)
	close       func() error
	writeHeader func(int, http.Header)
}

func (cw testCacheWriter) WriteHeader(s int, h http.Header) {
	cw.writeHeader(s, h)
}

func (cw testCacheWriter) Write(p []byte) (n int, err error) {
	return cw.write(p)
}

func (cw testCacheWriter) Close() error {
	return cw.close()
}

func newTestCacheWriter(cacheId string, k caching.Key) caching.CacheWriter {
	return &testCacheWriter{
		write: func(p []byte) (n int, err error) {
			return 0, nil
		},
		close: func() error {
			return nil
		},
		writeHeader: func(int, http.Header) {

		},
	}
}

func (c *testCache) GetWriter(cacheId string, k caching.Key, revalidate bool) caching.CacheWriter {
	return c.getWriter(cacheId, k, revalidate)
}

func NewTestCache(s string, get func(string, []caching.Key, http.ResponseWriter, *apexlog.Logger) (caching.CacheResult, caching.Key, error)) *testCache {
	return &testCache{cacheId: s, get: get}
}

func NewTestCacheGet(s string, get func(string, []caching.Key, http.ResponseWriter, *apexlog.Logger) (caching.CacheResult, caching.Key, error)) *testCache {
	return &testCache{cacheId: s, get: get, getWriter: func(cacheId string, k caching.Key, revalidate bool) caching.CacheWriter {
		return newTestCacheWriter(cacheId, k)
	}}
}

func testConfig() *config.Config {
	return &config.Config{
		Port:           0,
		MappingURL:     "",
		RoutingSecrets: []string{"a"},
	}
}

func rulesWithCacheId(t *testing.T, cacheId string, originServer *httptest.Server, sh *ServerHelper) *proxy.Rules {
	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:          "/t/*",
			Destination:   fmt.Sprintf("%s/$1", originServer.URL),
			Internal:      false,
			Recompression: false,
			CacheId:       cacheId,
		},
	}, sh.Logger)
	if err != nil || rules == nil {
		t.Fatal("Bad rules")
	}

	return rules
}

func rulesWithCacheIdRestartOnRedirect(t *testing.T, cacheId string, restartOnRedirect bool, originServer *httptest.Server, sh *ServerHelper) *proxy.Rules {
	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:              "/t/*",
			Destination:       fmt.Sprintf("%s/$1", originServer.URL),
			Internal:          false,
			Recompression:     false,
			CacheId:           cacheId,
			RestartOnRedirect: restartOnRedirect,
		},
	}, sh.Logger)
	if err != nil || rules == nil {
		t.Fatal("Bad rules")
	}

	return rules
}

func rulesWithCacheIdRestartOnRedirectRequestHeaders(t *testing.T, cacheId string, restartOnRedirect bool, requestHeaders map[string]interface{}, originServer *httptest.Server, sh *ServerHelper) *proxy.Rules {
	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:              "/t/*",
			Destination:       fmt.Sprintf("%s/$1", originServer.URL),
			Internal:          false,
			Recompression:     false,
			CacheId:           cacheId,
			RestartOnRedirect: restartOnRedirect,
			RequestHeaders:    requestHeaders,
		},
	}, sh.Logger)
	if err != nil || rules == nil {
		t.Fatal("Bad rules")
	}

	return rules
}

func rulesWithCacheIdRestartOnRedirectRecompression(t *testing.T, cacheId string, RestartOnRedirect bool, recompression bool, originServer *httptest.Server, sh *ServerHelper) *proxy.Rules {
	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:              "/t/*",
			Destination:       fmt.Sprintf("%s/$1", originServer.URL),
			Internal:          false,
			Recompression:     recompression,
			CacheId:           cacheId,
			RestartOnRedirect: RestartOnRedirect,
		},
	}, sh.Logger)
	if err != nil || rules == nil {
		t.Fatal("Bad rules")
	}

	return rules
}

func rulesWithCacheIdRestartOnRedirectResponseHeaders(t *testing.T, cacheId string, RestartOnRedirect bool, responseHeaders map[string]string, originServer *httptest.Server, sh *ServerHelper) *proxy.Rules {
	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:              "/t/*",
			Destination:       fmt.Sprintf("%s/$1", originServer.URL),
			Internal:          false,
			Recompression:     false,
			CacheId:           cacheId,
			RestartOnRedirect: RestartOnRedirect,
			ResponseHeaders:   responseHeaders,
		},
	}, sh.Logger)
	if err != nil || rules == nil {
		t.Fatal("Bad rules")
	}

	return rules
}

func rulesWithCacheIdRevalidate(t *testing.T, cacheId string, forceRevalidate int, originServerURL string, sh *ServerHelper) *proxy.Rules {
	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Path:            "/t/*",
			Destination:     fmt.Sprintf("%s/$1", originServerURL),
			Internal:        false,
			Recompression:   false,
			CacheId:         cacheId,
			ForceRevalidate: forceRevalidate,
		},
	}, sh.Logger)
	if err != nil || rules == nil {
		t.Fatal("Bad rules")
	}

	return rules
}

func listenerWithCache(cache caching.Cache, rules *proxy.Rules, logger *apexlog.Logger, conf *config.Config) *httptest.Server {
	router := proxy.NewRouter(rules, logger, conf)
	smux := http.NewServeMux()
	server.ConfigureServeMux(smux, conf, router, logger, cache)

	return httptest.NewServer(smux)
}

func listenerAndRouterWithCache(cache caching.Cache, rules *proxy.Rules, logger *apexlog.Logger, conf *config.Config) (*httptest.Server, proxy.Router) {
	router := proxy.NewRouter(rules, logger, conf)
	smux := http.NewServeMux()
	server.ConfigureServeMux(smux, conf, router, logger, cache)

	return httptest.NewServer(smux), router
}
