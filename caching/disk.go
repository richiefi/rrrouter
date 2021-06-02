package caching

import (
	"encoding/json"
	"fmt"
	apexlog "github.com/apex/log"
	"github.com/pkg/errors"
	"github.com/pkg/xattr"
	"github.com/richiefi/rrrouter/util"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

type Storage interface {
	GetWriter(Key, bool, *chan Key) StorageWriter
	Get([]Key) (*os.File, StorageMetadata, Key, error)
	Id() string
	Update(cfg StorageConfiguration)
	SetIsReplaced()
}

type StorageMetadata struct {
	Host           string
	Path           string
	RequestHeader  http.Header
	ResponseHeader http.Header
	Status         int
	RedirectedURL  string
	Created        int64
	Revalidated    int64
	Size           int64
}

func encodeStorageMetadata(sm StorageMetadata) ([]byte, error) {
	b, err := json.Marshal(sm)
	if err != nil {
		fmt.Printf("Failed to serialize %v\n", sm)
		return []byte{}, err
	}
	return b, nil
}

func decodeStorageMetadata(b []byte) (StorageMetadata, error) {
	sm := StorageMetadata{}
	err := json.Unmarshal(b, &sm)
	if err != nil {
		return StorageMetadata{}, err
	}
	return sm, nil
}

type StorageWriter interface {
	io.WriteCloser
	io.ReadSeeker
	http.Flusher
	WriteHeader(int, http.Header)
	ChangeKey(Key) error
	Abort() error
	WrittenFile() (*os.File, error)
}

type DiskStorage struct {
	Storage
}

func NewDiskStorage(id string, path string, size int64, logger *apexlog.Logger, now func() time.Time) Storage {
	createStoragePath(path)
	s := &storage{
		id:                id,
		path:              path,
		maxSizeBytes:      size,
		sizeBytes:         0,
		itemsLock:         sync.Mutex{},
		withAccessTime:    make(map[itemName]accessedItem, 0),
		withoutAccessTime: make(map[itemName]item, 0),
		logger:            logger,
		now:               now,
	}

	go s.runSizeLimiter()

	return s
}

func createStoragePath(path string) {
	exists, err := pathExists(path)
	if err != nil {
		panic(fmt.Sprintf("Storage can't use path %v: %v", path, err))
	} else if !exists {
		err := os.Mkdir(path, 0755)
		if err != nil {
			panic(fmt.Sprintf("Could not create storage path %v. Can't continue.", path))
		}
	}
}

type accessTime uint32
type itemName string

type storage struct {
	id                string
	path              string
	maxSizeBytes      int64
	startedAt         int64
	sizeBytes         int64
	itemsLock         sync.Mutex
	withAccessTime    map[itemName]accessedItem
	withoutAccessTime map[itemName]item
	isReplaced        bool

	logger *apexlog.Logger
	now    func() time.Time
}

type accessedItem struct {
	accessTime    accessTime
	sizeKilobytes uint32
}

type item struct {
	sizeKilobytes uint32
}

type sortingItem struct {
	name       itemName
	accessTime accessTime
}

type purgeableItems struct {
	withAccessTimes    []itemName
	withoutAccessTimes []itemName
	size               int64
}

func (s *storage) GetWriter(key Key, revalidate bool, closeNotifier *chan Key) StorageWriter {
	fp := filepath.Join(s.path, key.FsName())
	exists, err := pathExists(fp)
	if err != nil {
		panic(fmt.Sprintf("Storage failed to assess path %v: %v", fp, err))
	}
	if exists && !revalidate {
		return nil
	}

	return &storageWriter{key: key,
		root:           s.path,
		path:           fp,
		wasRevalidated: revalidate,
		closeFinisher: func(name string, size int64) {
			s.itemsLock.Lock()
			s.withAccessTime[itemName(name)] = accessedItem{
				accessTime:    accessTime(time.Now().Unix() - s.startedAt),
				sizeKilobytes: uint32(size / 1024),
			}
			s.sizeBytes += size
			s.itemsLock.Unlock()
		}, now: func() time.Time {
			return s.now()
		}, closeNotifier: closeNotifier,
		log: s.logger}
}

const (
	metadataXAttrName = "user.rrrouter"
)

func (s *storage) Get(keys []Key) (*os.File, StorageMetadata, Key, error) {
	if len(keys) == 0 {
		return nil, StorageMetadata{}, Key{}, nil
	}

	for _, key := range keys {
		fp := filepath.Join(s.path, key.FsName())

		f, err := os.Open(fp)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, StorageMetadata{}, key, err
		}

		sm, err := getStorageMetadata(f, metadataXAttrName)
		if err != nil {
			s.logger.Errorf("Failed to get metadata from %v: %v\n", fp, err)
			err := os.Remove(fp)
			if err != nil {
				s.logger.Errorf("Could not remove errored path %v: %v", fp, err)
				return nil, StorageMetadata{}, key, err
			}
			continue
		}

		return f, sm, key, nil
	}

	return nil, StorageMetadata{}, keys[0], os.ErrNotExist
}

func getStorageMetadata(f *os.File, attrName string) (StorageMetadata, error) {
	xattrb, err := xattr.FGet(f, attrName)
	if err != nil {
		return StorageMetadata{}, err
	}

	sm, err := decodeStorageMetadata(xattrb)
	if err != nil {
		return StorageMetadata{}, err
	}

	return sm, nil
}

func (s *storage) Id() string {
	return s.id
}

func (s *storage) Update(cfg StorageConfiguration) {
	if s.id != cfg.Id {
		return
	}
	if s.path != cfg.Path {
		createStoragePath(cfg.Path)
	}
	s.path = cfg.Path
	s.maxSizeBytes = int64(cfg.Size)
}

func (s *storage) SetIsReplaced() {
	s.isReplaced = true
}

func (s *storage) stats() string {
	return fmt.Sprintf("Storage %v: %v / %v MB (%.1f%%) in use.", s.id, s.sizeBytes/1024/1024, s.maxSizeBytes/1024/1024, float64(s.sizeBytes)/float64(s.maxSizeBytes)*100)
}

func (s *storage) readFiles(path string) int {
	d, err := os.Open(path)
	if err != nil {
		panic(fmt.Sprintf("Can't open storage path %v: %v\n", path, err))
	}
	fileCount := 0
	var names []string
	for err != io.EOF {
		names, err = d.Readdirnames(1024)
		if err != nil && err != io.EOF {
			panic(fmt.Sprintf("Can't list storage path %v: %v\n", s.path, err))
		}
		for _, n := range names {
			fileCount += 1
			fi, err := os.Stat(path + "/" + n)
			if err != nil {
				s.logger.Errorf("Error listing file: %v", err)
				continue
			}
			if fi.IsDir() {
				fileCount += s.readFiles(filepath.Join(path, n))
				continue
			}
			name := fi.Name()
			size := fi.Size()
			s.sizeBytes += size
			s.withoutAccessTime[itemName(prefixWithItemName(name)+name)] = item{sizeKilobytes: uint32(size / 1024)}
		}
	}

	return fileCount
}

func (s *storage) runSizeLimiter() {
	t := time.Now()
	fileCount := s.readFiles(s.path)
	s.logger.Infof("Read sizes of %v files in %v: %v", fileCount, time.Now().Sub(t), s.sizeBytes)

	// Initialization done, go at it forever:

	sleepTime := time.Second * 5
	for {
		if s.isReplaced {
			break
		}
		purgeable := purgeableItems{}
		s.itemsLock.Lock()
		s.logger.Info(s.stats())
		if s.sizeBytes > s.maxSizeBytes {
			purgeable = s.purgeableItemNames(s.sizeBytes - s.maxSizeBytes)
		}
		s.itemsLock.Unlock()
		if len(purgeable.withAccessTimes) == 0 && len(purgeable.withoutAccessTimes) == 0 {
			time.Sleep(sleepTime)
			continue
		}

		//s.logger.Debugf("with access time: %v", s.withAccessTime)
		//s.logger.Debugf("without access time: %v", s.withoutAccessTime)
		removedWithoutAccessTimes := []itemName{}
		removedWithAccessTimes := []itemName{}
		rmFiles := func(ins *[]itemName, removed *[]itemName) {
			for _, name := range *ins {
				fsPath := filepath.Join(s.path, string(name))
				err := os.Remove(fsPath)
				if err != nil {
					if os.IsNotExist(err) {
						s.logger.Infof("File had been removed already %v: %v", fsPath, err)
					} else {
						s.logger.Infof("Failed to remove file %v: %v", fsPath, err)
						continue
					}
				}
				*removed = append(*removed, name)
			}
		}
		rmFiles(&purgeable.withoutAccessTimes, &removedWithoutAccessTimes)
		rmFiles(&purgeable.withAccessTimes, &removedWithAccessTimes)

		s.itemsLock.Lock()
		for _, n := range removedWithAccessTimes {
			sizeKb := s.withAccessTime[n].sizeKilobytes
			delete(s.withAccessTime, n)
			s.sizeBytes -= int64(sizeKb * 1024)
		}
		for _, n := range removedWithoutAccessTimes {
			sizeKb := s.withoutAccessTime[n].sizeKilobytes
			delete(s.withoutAccessTime, n)
			s.sizeBytes -= int64(sizeKb * 1024)
		}
		s.itemsLock.Unlock()

		s.logger.Infof("Removed %v / %v items to release at least %v MB",
			len(removedWithoutAccessTimes)+len(removedWithAccessTimes), len(purgeable.withoutAccessTimes)+len(purgeable.withAccessTimes), purgeable.size/1024/1024)
		time.Sleep(sleepTime)
	}
}

func (s *storage) sortItems(items map[int64]item) {
	keys := make([]int64, len(items))
	i := 0
	for at := range items {
		keys[i] = at
		i++
	}
	sort.Slice(keys, func(i int, j int) bool { return keys[i] < keys[j] })
}

func (s *storage) purgeableItemNames(purgeBytes int64) purgeableItems {
	// 1. look for items without access times and start with them
	withoutAccessTimes := make([]itemName, 0)
	var bytesFound int64
	for name, item := range s.withoutAccessTime {
		withoutAccessTimes = append(withoutAccessTimes, name)
		bytesFound += int64(item.sizeKilobytes * 1024)
		if bytesFound >= purgeBytes {
			s.logger.Infof("Could satisfy purgeable from %v items without access time", len(s.withoutAccessTime))
			return purgeableItems{withoutAccessTimes: withoutAccessTimes, size: bytesFound}
		}
	}
	// 2. if not satisfied, continue with items with access times
	s.logger.Infof("Looking for purgeable from %v items with access time", len(s.withAccessTime))
	accessedItems := make([]sortingItem, len(s.withAccessTime))
	i := 0
	for name, ai := range s.withAccessTime {
		accessedItems[i] = sortingItem{name: name, accessTime: ai.accessTime}
		i++
	}
	withAccessTimes := make([]itemName, 0)
	sort.Slice(accessedItems, func(i int, j int) bool { return accessedItems[i].accessTime < accessedItems[j].accessTime })
	for i := range accessedItems {
		k := accessedItems[i].name
		item := s.withAccessTime[k]
		withAccessTimes = append(withAccessTimes, k)
		bytesFound += int64(item.sizeKilobytes * 1024)
		if bytesFound >= purgeBytes {
			break
		}
	}

	return purgeableItems{withAccessTimes: withAccessTimes, withoutAccessTimes: withoutAccessTimes, size: bytesFound}
}

type storageWriter struct {
	key            Key
	oldKey         *Key
	root           string
	path           string
	invalidated    bool
	errored        bool
	closeFinisher  func(name string, size int64)
	closeNotifier  *chan Key
	closed         bool
	fd             *os.File
	writtenStatus  int
	responseHeader http.Header
	redirectedURL  *url.URL
	created        int64
	writtenSize    int64
	log            *apexlog.Logger
	wasRevalidated bool
	now            func() time.Time
}

func (sw *storageWriter) Seek(offset int64, whence int) (int64, error) {
	return 0, nil
}

func (sw *storageWriter) Read(p []byte) (n int, err error) {
	return 0, nil
}

func (sw *storageWriter) WriteHeader(s int, h http.Header) {
	dirs := GetCacheControlDirectives(h)
	if (s != 200 && !IsCacheableError(s) && !util.IsRedirect(s)) || dirs.DoNotCache() {
		sw.invalidated = true
		return
	} else {
		sw.writtenStatus = s
		if IsCacheableError(s) {
			h.Set("cache-control", "s-maxage=60, max-age=60")
		}
		sw.responseHeader = util.DenyHeaders(h, []string{HeaderRrrouterCacheStatus})
	}

	if sw.created == 0 {
		sw.created = time.Now().Unix()
	}
	if sw.fd == nil {
		err := createAllSubdirs(filepath.Dir(sw.path))
		if err != nil {
			sw.log.Errorf("Could not create directory for path: %v", sw.path)
			sw.errored = true
			sw.notify()
			return
		}
		fd, err := os.Create(sw.path)
		if err != nil {
			exists, _ := pathExists(sw.path)
			if !exists {
				sw.log.Errorf("Could not create file at path %v: %v", sw.path, err)
				sw.errored = true
				sw.notify()
				return
			} else {
				fd, err = os.OpenFile(sw.path, os.O_RDWR, 0)
				if err != nil {
					sw.log.Errorf("Can't open existing file for reading and writing: %v", sw.path)
					sw.errored = true
					sw.notify()
					return
				}
			}
		}
		sw.fd = fd
	}
}

func createAllSubdirs(dir string) error {
	_, err := os.Stat(dir)
	if err == nil || !os.IsNotExist(err) {
		return nil
	}

	return os.MkdirAll(dir, 0755)
}

func (sw *storageWriter) Write(p []byte) (n int, err error) {
	if sw.invalidated {
		return n, nil
	} else if sw.errored {
		return 0, errors.New(fmt.Sprintf("Write called for errored %v", sw.key.FsName()))
	}

	nn, err := sw.fd.Write(p)
	sw.writtenSize += int64(nn)
	if rand.Intn(100) < 10 && sw.log != nil {
		sw.log.Debugf("DEBUG: Wrote, size is: %v", sw.writtenSize)
	}

	return nn, err
}

func (sw *storageWriter) Close() error {
	if sw.closed == true {
		sw.log.Warnf("Tried to close an already closed storageWriter: %v", sw.key.FsName())
		return nil
	} else if sw.errored {
		return errors.New("Close called for errored writer")
	}

	var revalidatedMetadata *StorageMetadata
	if sw.fd == nil {
		if sw.wasRevalidated {
			fd, err := os.OpenFile(sw.path, os.O_RDWR, 0)
			if err != nil {
				sw.log.Errorf("Could not reopen file for revalidation state saving: %v", err)
				return err
			}
			sm, err := getStorageMetadata(fd, metadataXAttrName)
			if err != nil {
				return err
			}
			sm.Revalidated = sw.now().Unix()
			revalidatedMetadata = &sm
			sw.fd = fd
		} else {
			return nil
		}
	}

	err := sw.fd.Close()
	if err != nil {
		return err
	}

	if sw.invalidated {
		err := os.Remove(sw.path)
		if err != nil {
			sw.log.Warnf("Could not remove invalidated path %v: %v", sw.path, err)
		}
		return err
	}

	if cl := sw.responseHeader.Get("content-length"); len(cl) > 0 {
		if contentLength, err := strconv.Atoi(cl); err != nil && contentLength > 0 {
			if int64(contentLength) != sw.writtenSize {
				sw.log.Error(fmt.Sprintf("Written size %v did not match Content-Length header size %v. Deleting stored file.\n", sw.writtenSize, contentLength))
				return sw.Abort()
			}
		}
	}

	var metadata StorageMetadata
	if revalidatedMetadata == nil {
		var revalidated int64
		if sw.wasRevalidated {
			revalidated = sw.now().Unix()
		} else {
			revalidated = 0
		}
		var redirectedURL string
		if sw.redirectedURL != nil {
			redirectedURL = sw.redirectedURL.String()
		}
		metadata = StorageMetadata{
			Host:           sw.key.host,
			Path:           sw.key.path,
			RequestHeader:  sw.key.storedHeaders,
			ResponseHeader: sw.responseHeader,
			Status:         sw.writtenStatus,
			RedirectedURL:  redirectedURL,
			Created:        sw.created,
			Revalidated:    revalidated,
			Size:           sw.writtenSize,
		}
	} else {
		metadata = *revalidatedMetadata
	}

	esm, err := encodeStorageMetadata(metadata)
	if err != nil {
		return err
	}

	err = xattr.Set(sw.path, metadataXAttrName, esm)
	if err != nil {
		return err
	}

	if sw.closeFinisher != nil {
		sw.closeFinisher(sw.key.FsName(), sw.writtenSize)
	}

	sw.notify()
	sw.closed = true

	return err
}

func (sw *storageWriter) notify() {
	if sw.closeNotifier != nil {
		*sw.closeNotifier <- sw.key
		if sw.oldKey != nil {
			sw.log.Debugf("Had old key: %v", *sw.oldKey)
			*sw.closeNotifier <- *sw.oldKey
		}
	}
}

func (sw *storageWriter) WrittenFile() (*os.File, error) {
	if sw.invalidated {
		return nil, nil
	}

	fd, err := os.Open(sw.path)
	if err != nil {
		return nil, err
	}

	return fd, nil
}

func (sw *storageWriter) ChangeKey(k Key) error {
	sw.log.Debugf("1: Gonna change %v to %v\n%v VS. %v\n", sw.key.FsName(), k.FsName(), sw.key, k)
	newPath := filepath.Join(sw.root, k.FsName())
	exists, err := pathExists(newPath)
	if err != nil {
		return err
	}
	if !exists {
		oldExists, err := pathExists(sw.path)
		if err != nil {
			return err
		}
		if oldExists {
			err = os.Rename(sw.path, newPath)
			if err != nil {
				return err
			}
		}
	}

	sw.path = newPath
	oldKey := &Key{host: sw.key.host, path: sw.key.path, opaqueOrigin: sw.key.opaqueOrigin,
		storedHeaders: sw.key.storedHeaders.Clone(), originalHeaders: sw.key.originalHeaders.Clone()}
	sw.oldKey = oldKey
	sw.key = k

	return nil
}

func (sw *storageWriter) SetRedirectedURL(redir *url.URL) {
	sw.redirectedURL = redir
}

func (sw *storageWriter) SetRevalidated() {
	sw.wasRevalidated = true
}

func (sw *storageWriter) Abort() error {
	closeErr := sw.fd.Close()
	err := os.Remove(sw.path)
	if err != nil {
		sw.log.Errorf("Could not remove path %v: %v. Close error was: %v", sw.path, err, closeErr)
		return err
	}

	return nil
}

func (sw *storageWriter) Flush() {

}

// Helpers

func pathExists(p string) (bool, error) {
	if _, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		} else {
			return false, err
		}
	}

	return true, nil
}
