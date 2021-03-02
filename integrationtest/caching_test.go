// +build integration

package integrationtest

import (
	"fmt"
	apexlog "github.com/apex/log"
	"github.com/c2h5oh/datasize"
	"github.com/richiefi/rrrouter/caching"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
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
			})
		cw, _ := sw.(caching.CacheWriter)

		writer := caching.NewCachingResponseWriter(w, cw, l)

		return caching.CacheResult{caching.NotFoundWriter, nil, writer, nil, caching.CacheMetadata{Header: nil, Status: 200}, 0, false}, keys[0], nil
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
			return caching.CacheResult{caching.Found, f, nil, nil, caching.CacheMetadata{Header: nil, Status: 200}, 0, false}, keys[0], nil
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
			})
		cw, _ := sw.(caching.CacheWriter)
		writer := caching.NewCachingResponseWriter(w, cw, l)

		return caching.CacheResult{caching.NotFoundWriter, nil, writer, nil, caching.CacheMetadata{Header: nil, Status: 200}, 0, false}, keys[0], nil
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
	}, nil)

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 1, timesOriginHit)

	now = now.Add(time.Minute * 1)
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

	rules := rulesWithCacheIdRevalidate(t, "disk1", 10, originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	}, nil)

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, 1, timesOriginHit)

	now = now.Add(time.Second * 10)
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

	rules := rulesWithCacheIdRevalidate(t, "disk1", 10, originServer, sh)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	}, nil)

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "1", resp.Header.Get("etag"))
	require.Equal(t, 1, timesOriginHit)

	now = now.Add(time.Second * 10)
	hdrs = map[string]string{"expires": now.Add(time.Minute * 1).Format(time.RFC1123), "etag": "1", "cache-control": "public", "vary": "origin"}
	originBody = []byte("AB")

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"if-none-match": []string{"1"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, []byte("AB"), body)
	require.Equal(t, "revalidated", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "1", resp.Header.Get("etag"))
	require.Equal(t, 2, timesOriginHit)

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("AB"), body)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
	require.Equal(t, "1", resp.Header.Get("etag"))
	require.Equal(t, 2, timesOriginHit)

	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{"if-none-match": []string{"2"}})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, 304, resp.StatusCode)
	require.Equal(t, []byte(""), body)
	require.Equal(t, "1", resp.Header.Get("etag"))
	require.Equal(t, "origin", resp.Header.Get("vary"))
	require.Equal(t, "public", resp.Header.Get("cache-control"))
	require.Equal(t, now.Add(time.Minute*1).Format(time.RFC1123), resp.Header.Get("expires"))
	require.Equal(t, 2, timesOriginHit)
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
	}, nil)

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 1, timesOriginHit)
	//require.Equal(t, true, <-closeChan)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Minute * 1)

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
	//closeChan := make(chan bool)
	c := caching.NewCacheWithOptions([]caching.StorageConfiguration{{Size: datasize.MB * 1, Path: t.TempDir(), Id: "disk1"}}, sh.Logger, func() time.Time {
		return now
	}, nil)

	listener := listenerWithCache(c, rules, sh.Logger, testConfig())
	defer listener.Close()

	resp := sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body := sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 1, timesOriginHit)
	//require.Equal(t, true, <-closeChan)
	require.Equal(t, "miss", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Minute * 1)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 2, timesOriginHit)
	//require.Equal(t, true, <-closeChan)
	require.Equal(t, "revalidated", resp.Header.Get("richie-edge-cache"))

	now = now.Add(time.Second * 30)
	resp = sh.getURLQuery("/t/asdf", listener.URL, url.Values{}, http.Header{})
	defer resp.Body.Close()
	body = sh.readBody(resp)
	require.Equal(t, []byte("ab"), body)
	require.Equal(t, 2, timesOriginHit)
	require.Equal(t, "hit", resp.Header.Get("richie-edge-cache"))
}

func TestCache_cache_control_private_not_cached(t *testing.T) {
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
	}, nil)

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
	}, nil)

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
	}, nil)

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
	}, nil)

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
	}, nil)

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

type entry struct {
	reader         *os.File
	headerStatus   caching.CacheMetadata
	age            int
	mustRevalidate bool
}

type testCache struct {
	caching.Cache
	cacheId     string
	cachedEntry *entry
	get         func(string, []caching.Key, http.ResponseWriter, *apexlog.Logger) (caching.CacheResult, caching.Key, error)
	getWriter   func(cacheId string, k caching.Key, revalidate bool) caching.CacheWriter
}

func (c *testCache) Get(s string, ri int, keys []caching.Key, w http.ResponseWriter, l *apexlog.Logger) (caching.CacheResult, caching.Key, error) {
	if s != c.cacheId {
		return caching.CacheResult{caching.NotFoundReader, nil, nil, nil, caching.CacheMetadata{Header: http.Header{}, Status: 200}, 0, false}, keys[0], nil
	}

	if e := c.cachedEntry; e != nil {
		return caching.CacheResult{caching.Found, e.reader, nil, nil, e.headerStatus, int64(e.age), e.mustRevalidate}, keys[0], nil
	}

	return c.get(s, keys, w, l)
}

func (c *testCache) HasStorage(id string) bool {
	return true
}

type testStorageWriter struct {
	caching.StorageWriter
	write       func(p []byte) (n int, err error)
	close       func() error
	writeHeader func(int, http.Header)
	writtenFile func() (*os.File, error)
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

func NewTestStorageWriter(write func(p []byte) (n int, err error), close func() error, writeHeader func(int, http.Header), writtenFile func() (*os.File, error)) caching.StorageWriter {
	return &testStorageWriter{
		write:       write,
		close:       close,
		writeHeader: writeHeader,
		writtenFile: writtenFile,
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
			Pattern:       "127.0.0.1/t/*",
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

func rulesWithCacheIdRevalidate(t *testing.T, cacheId string, forceRevalidate int, originServer *httptest.Server, sh *ServerHelper) *proxy.Rules {
	rules, err := proxy.NewRules([]proxy.RuleSource{
		{
			Pattern:         "127.0.0.1/t/*",
			Destination:     fmt.Sprintf("%s/$1", originServer.URL),
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
