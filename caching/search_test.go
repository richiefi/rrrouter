package caching

import (
	"github.com/stretchr/testify/require"
	"math/rand"
	"testing"
	"time"
)

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

var bSearch *Search
var bUrls []string
var bKeyValues map[string][]string

const nCacheValues = 35000
const nURLWithCacheTag = 50
const nURLWithoutCacheTag = 50

func setupBenchmarkedSearch() (*Search, []string, map[string][]string) {
	if bSearch != nil && bUrls != nil && bKeyValues != nil {
		return bSearch, bUrls, bKeyValues
	}
	se := NewSearch([]string{"cache-tag"})
	kvs := make(map[string][]string)
	rand.Seed(time.Now().UnixNano())
	for n := 0; n < nCacheValues; n++ {
		kvs["cache-tag"] = append(kvs["cache-tag"], randSeq(64))
	}
	vv, _ := kvs["cache-tag"]
	urls := []string{}
	empty := make(map[string][]string)
	for _, v := range vv {
		m := make(map[string][]string)
		m["cache-tag"] = []string{v}
		for i := 0; i < nURLWithCacheTag; i++ {
			u := "https://" + randSeq(160)
			urls = append(urls, u)
			<-se.Insert(m, u, "/path/"+randSeq(64))
		}
		for i := 0; i < nURLWithoutCacheTag; i++ {
			u := "https://" + randSeq(160)
			urls = append(urls, u)
			<-se.Insert(empty, u, "/path/"+randSeq(64))
		}
	}
	bSearch = &se
	bUrls = urls
	bKeyValues = kvs
	return &se, urls, kvs
}

func Benchmark_kv_search(b *testing.B) {
	se, _, kvs := setupBenchmarkedSearch()
	keys := []string{}
	for k, _ := range kvs {
		keys = append(keys, k)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := 0
		idx := rand.Intn(len(keys))
		key := keys[idx]
		vals, _ := kvs[key]
		randN := rand.Intn(len(vals))
		searchedValue := ""
		for _, v := range vals {
			if n == randN {
				searchedValue = v
				break
			}
			n += 1
		}
		entries := (*se).ByKeyValue("cache-tag", searchedValue)
		require.Equal(b, nURLWithCacheTag, len(entries))
	}
}

func Benchmark_url_wildcard_search(b *testing.B) {
	se, urls, _ := setupBenchmarkedSearch()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		searchedUrl := urls[rand.Intn(len(urls)-1)]
		entries, err := (*se).ByURLPattern(searchedUrl[:len(searchedUrl)-20] + "*")
		require.Nil(b, err)
		require.Equal(b, 1, len(entries))
	}
}

func Benchmark_url_equality_search(b *testing.B) {
	se, urls, _ := setupBenchmarkedSearch()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		searchedUrl := urls[rand.Intn(len(urls)-1)]
		entries, err := (*se).ByURLPattern(searchedUrl)
		require.Nil(b, err)
		require.Equal(b, 1, len(entries))
	}
}

func TestSearch_key_value_search(t *testing.T) {
	se := NewSearch([]string{"cache-tag"})

	kvs := make(map[string][]string)
	kvs["cache-tag"] = []string{"abcd"}
	u := "https://example.com/abcd?e=f"
	ep := "a/b/c/abcd"
	<-se.Insert(kvs, u, ep)

	entries := se.ByKeyValue("cache-tag", "abcd")
	require.Equal(t, 1, len(entries))
	require.Equal(t, entry(ep), entries[0])
}

func TestSearch_key_value_search_multiple_urls(t *testing.T) {
	se := NewSearch([]string{"cache-tag"})

	kvs := make(map[string][]string)
	kvs["cache-tag"] = []string{"abcd"}
	u := "https://example.com/abcd?e=f"
	ep := "a/b/c/abcd"
	<-se.Insert(kvs, u, ep)

	entries := se.ByKeyValue("cache-tag", "abcd")
	require.Equal(t, 1, len(entries))
	require.Equal(t, entry(ep), entries[0])

	u2 := "https://example.com/abcd?e=f2"
	ep2 := "a/b/c/abcd"
	<-se.Insert(kvs, u2, ep2)
	entries = se.ByKeyValue("cache-tag", "abcd")
	require.Equal(t, 2, len(entries))
	require.Equal(t, entry(ep), entries[0])
	require.Equal(t, entry(ep2), entries[1])
}

func TestSearch_key_value_search_overlapping_urls(t *testing.T) {
	se := NewSearch([]string{"cache-tag"})

	kvs := make(map[string][]string)
	kvs["cache-tag"] = []string{"abcd"}
	u := "https://example.com/abcd?e=f"
	ep := "a/b/c/abcd"
	<-se.Insert(kvs, u, ep)

	entries := se.ByKeyValue("cache-tag", "abcd")
	require.Equal(t, 1, len(entries))
	require.Equal(t, entry(ep), entries[0])

	u2 := "https://example.com/abcd?e=f"
	ep2 := "a/b/c/abcde"
	<-se.Insert(kvs, u2, ep2)
	entries = se.ByKeyValue("cache-tag", "abcd")
	require.Equal(t, 2, len(entries))
	require.Equal(t, entry(ep), entries[0])
	require.Equal(t, entry(ep2), entries[1])
}

func TestSearch_key_value_search_multiple_keys_and_urls(t *testing.T) {
	se := NewSearch([]string{"cache-tag", "x-amz-unionize"})

	kvs := make(map[string][]string)
	kvs["cache-tag"] = []string{"abcd"}
	kvs["x-amz-unionize"] = []string{"true"}
	u := "https://example.com/abcd?e=f"
	ep := "a/b/c/abcd"
	<-se.Insert(kvs, u, ep)

	entries := se.ByKeyValue("cache-tag", "abcd")
	require.Equal(t, 1, len(entries))
	require.Equal(t, entry(ep), entries[0])

	u2 := "https://example.com/abcd?e=fg"
	ep2 := "a/b/c/abcde"
	<-se.Insert(kvs, u2, ep2)
	entries = se.ByKeyValue("cache-tag", "abcd")
	require.Equal(t, 2, len(entries))
	require.Equal(t, entry(ep), entries[0])
	require.Equal(t, entry(ep2), entries[1])

	entries = se.ByKeyValue("x-amz-unionize", "true")
	require.Equal(t, 2, len(entries))
	require.Equal(t, entry(ep), entries[0])
	require.Equal(t, entry(ep2), entries[1])
}

func TestSearch_simple_url_search(t *testing.T) {
	se := NewSearch([]string{"cache-tag"})

	kvs := make(map[string][]string)
	u := "https://example.com/abcd?e=f"
	ep := "a/b/c/abcd"
	<-se.Insert(kvs, u, ep)

	entries, err := se.ByURLPattern(u)
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))
	require.Equal(t, entries[0], entry(ep))
}

func TestSearch_wildcard_url_search(t *testing.T) {
	se := NewSearch([]string{"cache-tag"})

	kvs := make(map[string][]string)
	<-se.Insert(kvs, "https://example.com/abcd?e=f", "a/b/c/abcd")
	<-se.Insert(kvs, "http://example.com/bcda", "b/c/d/bcda")

	entries, err := se.ByURLPattern("*://example.com*/bcda")
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))
	require.Equal(t, entries[0], entry("b/c/d/bcda"))
}

func TestSearch_by_path(t *testing.T) {
	se := NewSearch([]string{"cache-tag"})

	kvs := make(map[string][]string)
	<-se.Insert(kvs, "https://example.com/abcd?e=f", "a/b/c/abcd")
	<-se.Insert(kvs, "http://example.com/bcda", "b/c/d/bcda")

	u, err := se.ByPath("b/c/d/bcda")
	require.Nil(t, err)
	require.Equal(t, "http://example.com/bcda", u)
}

func TestSearch_remove_by_kv_only(t *testing.T) {
	se := NewSearch([]string{"cache-tag"})

	kvs := make(map[string][]string)
	<-se.Insert(kvs, "https://example.com/abcd", "a/b/c/abcd")
	kvs["cache-tag"] = []string{"abcd"}
	<-se.Insert(kvs, "https://example.com/abcd", "b/c/d/bcda")

	entries, err := se.ByURLPattern("https://example.com/abcd")
	require.Nil(t, err)
	require.Equal(t, 2, len(entries))

	rr := <-se.Remove("", &kvs, nil, nil)
	require.Nil(t, err)
	require.Equal(t, 1, rr.urls)
	require.Equal(t, 1, rr.entries)
	entries = se.ByKeyValue("cache-tag", "abcd")
	require.Equal(t, 0, len(entries))
	entries, err = se.ByURLPattern("https://example.com/abcd")
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))
}

func TestSearch_remove_by_kv_and_url(t *testing.T) {
	se := NewSearch([]string{"cache-tag"})

	kvs := make(map[string][]string)
	u := "https://example.com/abcd"
	<-se.Insert(kvs, u, "a/b/c/abcd")
	kvs["cache-tag"] = []string{"abcd"}
	<-se.Insert(kvs, u, "b/c/d/bcda")

	entries, err := se.ByURLPattern("https://example.com/abcd")
	require.Nil(t, err)
	require.Equal(t, 2, len(entries))

	rr := <-se.Remove("", &kvs, &u, nil)
	require.Nil(t, err)
	require.Equal(t, 1, rr.urls)
	require.Equal(t, 1, rr.entries)
	entries = se.ByKeyValue("cache-tag", "abcd")
	require.Equal(t, 0, len(entries))
	entries, err = se.ByURLPattern("https://example.com/abcd")
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))
}

func TestSearch_remove_by_kv_and_url_other_entry_with_same_cache_tag_not_matched_by_url(t *testing.T) {
	se := NewSearch([]string{"cache-tag"})

	kvs := make(map[string][]string)
	u := "https://example.com/abcd"
	kvs["cache-tag"] = []string{"abcd"}
	<-se.Insert(kvs, u, "b/c/d/bcda")
	u2 := "https://sub.example.com/abcd"
	<-se.Insert(kvs, u2, "e/f/g/efg0")

	entries, err := se.ByURLPattern("https://example.com/abcd")
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))

	wu := "https://exam*.com/*"
	rr := <-se.Remove("", &kvs, &wu, nil)
	require.Nil(t, err)
	require.Equal(t, 1, rr.urls)
	require.Equal(t, 1, rr.entries)
	entries = se.ByKeyValue("cache-tag", "abcd")
	require.Equal(t, 1, len(entries))
	entries, err = se.ByURLPattern("https://example.com/abcd")
	require.Nil(t, err)
	require.Equal(t, 0, len(entries))
	entries, err = se.ByURLPattern("https://sub.example.com/abcd")
	require.Nil(t, err)
	require.Equal(t, 1, len(entries))
}

func TestSearch_remove_by_url_only(t *testing.T) {
	se := NewSearch([]string{"cache-tag"})

	kvs := make(map[string][]string)
	u := "https://example.com/abcd"
	<-se.Insert(kvs, u, "a/b/c/abcd")
	kvs["cache-tag"] = []string{"abcd"}
	<-se.Insert(kvs, u, "b/c/d/abcd2")

	rr := <-se.Remove("", nil, &u, nil)
	require.Nil(t, rr.error)
	require.Equal(t, 2, rr.urls)
	require.Equal(t, 3, rr.entries)
	entries := se.ByKeyValue("cache-tag", "abcd")
	require.Equal(t, 0, len(entries))
	entries, err := se.ByURLPattern("https://example.com/abcd")
	require.Nil(t, err)
	require.Equal(t, 0, len(entries))
}

func TestSearch_remove_by_path(t *testing.T) {

}
