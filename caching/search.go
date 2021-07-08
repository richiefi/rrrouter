package caching

import (
	"errors"
	"fmt"
	"github.com/richiefi/rrrouter/proxy"
	"regexp"
	"sync"
	"time"
)

type Search interface {
	ByKeyValue(key string, value string) []entry
	ByURLPattern(pattern string) ([]entry, error)
	ByPath(name string) (string, error)
	Insert(keyValues map[string][]string, url string, path string) chan bool
	Remove(storagePath string, keyValues *map[string][]string, pattern *string, path *string) chan RemoveResult
}

type RemoveResult struct {
	urls    int
	entries int
	error   error
}

type key string
type value string
type urlString string
type entry string

type search struct {
	// map["Cache-Tag"]map["x-metadator-alibi"]map["https://..."][]{"a/b/e/abe...", ...}
	items              map[key]map[value]map[urlString][]entry
	itemsLock          sync.Mutex
	insertsRemoves     []func()
	insertsRemovesLock sync.Mutex
	allowedKeys        []string
}

func (s *search) ByKeyValue(k string, v string) (result []entry) {
	s.itemsLock.Lock()
	defer s.itemsLock.Unlock()

	urlStrings, ok := s.items[key(k)][value(v)]
	if !ok {
		return result
	}
	entries := []entry{}
	for _, vv := range urlStrings {
		for _, v := range vv {
			entries = append(entries, v)
		}
	}
	return entries
}

func (s *search) ByURLPattern(pattern string) (result []entry, err error) {
	s.itemsLock.Lock()
	defer s.itemsLock.Unlock()

	re, wildcardCount, err := proxy.RegexpWithString(pattern, false)
	if err != nil {
		return result, err
	}
	urlMap, ok := s.items[urlOnlyKey][urlOnlyValue]
	if !ok {
		return result, err
	}
	entries := []entry{}
	// If the pattern does not have wildcards we go for a faster string equality check. Should the expectations
	// change on what kind of patterns are supported, this should be changed to regexp only.
	for url, vv := range urlMap {
		if wildcardCount > 0 && re.Match([]byte(url)) {
			for _, v := range vv {
				entries = append(entries, v)
			}
		} else if url == urlString(pattern) {
			for _, v := range vv {
				entries = append(entries, v)
			}
			break
		}
	}
	return entries, err
}

func (s *search) ByPath(name string) (string, error) {
	s.itemsLock.Lock()
	defer s.itemsLock.Unlock()

	for _, vv := range s.items {
		for _, urlMap := range vv {
			for url, entries := range urlMap {
				for _, e := range entries {
					if string(e) == name {
						return string(url), nil
					}
				}
			}
		}
	}

	return "", errors.New("Not found")
}

const urlOnlyKey = "urlOnlyKey"
const urlOnlyValue = "urlOnlyValue"

func (s *search) insert(keyValues map[string][]string, url string, path string) {
	kvs := make(map[string][]string, len(keyValues))
	for k, vv := range keyValues {
		for _, v := range vv {
			kvs[k] = append(kvs[k], v)
		}
	}

	// Add a default key-value for searches which do not specify a key-value to filter with:
	kvs[urlOnlyKey] = []string{urlOnlyValue}

	for k, vv := range kvs {
		allowed := false
		for _, hk := range s.allowedKeys {
			if hk == k || k == urlOnlyKey {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}
		// map["Cache-Tag"]map["x-metadator-alibi"]
		valueMap, ok := s.items[key(k)]
		if !ok {
			valueMap = make(map[value]map[urlString][]entry)
			s.items[key(k)] = valueMap
		}
		for _, v := range vv {
			found := false
			var urlMap map[urlString][]entry
			urlMap, ok := valueMap[value(v)]
			if !ok {
				urlMap = make(map[urlString][]entry)
				valueMap[value(v)] = urlMap
			}
			var entries []entry
			entries, ok = urlMap[urlString(url)]
			if !ok {
				entries = []entry{}
				urlMap[urlString(url)] = entries
			}
			for _, e := range entries {
				if e == entry(path) {
					found = true
					break
				}
			}
			if !found {
				valueMap[value(v)][urlString(url)] = append(valueMap[value(v)][urlString(url)], entry(path))
			}
		}
	}
}

func (s *search) Insert(keyValues map[string][]string, url string, path string) chan bool {
	s.insertsRemovesLock.Lock()
	defer s.insertsRemovesLock.Unlock()

	c := make(chan bool, 1)
	var doInsert = func() {
		s.insert(keyValues, url, path)
		c <- true
	}
	s.insertsRemoves = append(s.insertsRemoves, doInsert)

	return c
}

func (s *search) Remove(storagePath string, keyValues *map[string][]string, url *string, path *string) chan RemoveResult {
	s.insertsRemovesLock.Lock()
	defer s.insertsRemovesLock.Unlock()

	c := make(chan RemoveResult, 1)
	var doRemove = func() {
		rr, err := s.remove(storagePath, keyValues, url, path)
		if err != nil {
			c <- RemoveResult{
				error: err,
			}
			return
		}
		c <- rr
	}
	s.insertsRemoves = append(s.insertsRemoves, doRemove)

	return c
}

func (s *search) remove(storagePath string, keyValues *map[string][]string, url *string, path *string) (RemoveResult, error) {
	rr := RemoveResult{}
	var re *regexp.Regexp
	var err error
	if url != nil {
		re, _, err = proxy.RegexpWithString(*url, false)
		if err != nil {
			return rr, err
		}
	}
	removeInByUrlOnlyEntries := make([]entry, 0)
	for k, vv := range s.items {
		foundKeyValues := map[key][]value{}
		foundUrls := []urlString{}
		for vk, urlMap := range vv {
			if keyValues != nil { // Searching by keyValues, filtering down with url, if present
				for sk, svv := range *keyValues {
					if key(sk) == k {
						for _, sv := range svv {
							if value(sv) == vk {
								if re != nil {
									for u, entries := range urlMap {
										if re.Match([]byte(u)) {
											foundUrls = append(foundUrls, u)
											rr.urls += 1
											rr.entries += len(entries)
											for _, e := range entries {
												removeInByUrlOnlyEntries = append(removeInByUrlOnlyEntries, e)
											}
										}
									}
									for _, u := range foundUrls {
										delete(urlMap, u)
									}
								} else {
									foundKeyValues[k] = append(foundKeyValues[k], vk)
									rr.urls += len(urlMap)
									for _, entries := range urlMap {
										rr.entries += len(entries)
										for _, e := range entries {
											removeInByUrlOnlyEntries = append(removeInByUrlOnlyEntries, e)
										}
									}
								}
							}
						}
					}
				}
			} else if re != nil { // Searching by url only
				for u, entries := range urlMap {
					if !re.Match([]byte(u)) {
						continue
					}
					foundUrls = append(foundUrls, u)
					rr.urls += 1
					rr.entries += len(entries)
				}
				for _, u := range foundUrls {
					delete(urlMap, u)
				}
			}
		}
		for k, vv := range foundKeyValues {
			for _, v := range vv {
				delete(s.items[k], v)
			}
		}
	}
	// Remove any entries found with a keyValues and/or url search from under the urlOnlyKey
	if len(removeInByUrlOnlyEntries) > 0 {
		if valueMap, ok := s.items[urlOnlyKey]; ok {
			for _, urlMap := range valueMap {
				for u, entries := range urlMap {
					tmp := entries[:0] // keep the underlying array-trick
					for _, entry := range entries {
						keep := true
						for _, e := range removeInByUrlOnlyEntries {
							if e == entry {
								keep = false
								break
							}
						}
						if keep {
							tmp = append(tmp, entry)
						}
					}
					urlMap[u] = tmp
				}
			}
		}
	}

	// todo: storagePath, path & os.Remove

	return rr, nil
}

func (s *search) inserterRemover() {
	for {
		var copiedInsertsRemoves []func()
		s.insertsRemovesLock.Lock()
		if len(s.insertsRemoves) > 0 {
			copiedInsertsRemoves = make([]func(), len(s.insertsRemoves))
			copy(copiedInsertsRemoves, s.insertsRemoves)
			s.insertsRemoves = make([]func(), 0)
		}
		s.insertsRemovesLock.Unlock()

		if len(copiedInsertsRemoves) > 0 {
			s.itemsLock.Lock()
			for _, f := range copiedInsertsRemoves {
				f()
			}
			fmt.Printf("ran insertRemoved %v\n times", len(copiedInsertsRemoves))
			s.itemsLock.Unlock()
		}
		time.Sleep(time.Millisecond * 100)
	}
}

func NewSearch(allowedKeys []string) Search {
	keyMap := make(map[key]map[value]map[urlString][]entry, 0)
	se := &search{
		items:              keyMap,
		itemsLock:          sync.Mutex{},
		insertsRemoves:     make([]func(), 0),
		insertsRemovesLock: sync.Mutex{},
		allowedKeys:        allowedKeys,
	}
	go se.inserterRemover()
	return se
}
