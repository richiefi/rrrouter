package caching

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	apexlog "github.com/apex/log"
	"github.com/getsentry/sentry-go"
	"github.com/pkg/errors"
	"github.com/pkg/xattr"
	mets "github.com/richiefi/rrrouter/metrics"
	"github.com/richiefi/rrrouter/util"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Storage interface {
	GetWriter(Key, bool, *chan KeyInfo) StorageWriter
	Get(context.Context, []Key) (*os.File, StorageMetadata, Key, error)
	Id() string
	Update(cfg StorageConfiguration)
	SetIsReplaced()
	WriteTest() (bool, error)
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
	FdSize         int64
}

func encodeStorageMetadata(sm StorageMetadata) []byte {
	return []byte(encodeCustom(&sm))
}

func decodeStorageMetadata(b []byte) (StorageMetadata, error) {
	sm := StorageMetadata{}
	err := decodeCustom(&sm, &b)
	if err != nil {
		err := json.Unmarshal(b, &sm)
		if err != nil {
			return StorageMetadata{}, err
		}
	}
	return sm, nil
}

func sToInt64(s *string) (int64, error) {
	return strconv.ParseInt(*s, 10, 64)
}

func sToHeader(h *http.Header, s *string) error {
	if !strings.HasPrefix(*s, "{") {
		return errors.New("Invalid format")
	}
	ts := strings.Trim(*s, "{}")
	if len(ts) == 0 {
		return nil
	}
	parts := strings.Split(ts, "],")
	partsLen := len(parts)
	for i, p := range parts {
		if i == 0 {
			p = p[0:]
		} else if i == partsLen-1 {
			p = p[:len(p)-1]
		}
		splat := strings.SplitN(p, ":", 2)
		if len(splat) != 2 {
			return errors.New(fmt.Sprintf("Odd header: %v", splat))
		}
		hk := splat[0]
		h.Set(hk, strings.Trim(splat[1], "[]"))
	}

	return nil
}

func headerToS(h *http.Header) string {
	if len(*h) == 0 {
		return "{}"
	}
	keys := make([]string, 0)
	for k, _ := range *h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s := ""
	i := 0
	keysLen := len(keys)
	for _, k := range keys {
		s += k + ":[" + h.Get(k) + "]"
		if i != keysLen-1 {
			s += ","
		}
		i++
	}
	return "{" + s + "}"
}

func encodeCustom(sm *StorageMetadata) string {
	s := ""
	s += sm.Host + "|"
	s += sm.Path + "|"
	s += headerToS(&sm.RequestHeader) + "|"
	s += headerToS(&sm.ResponseHeader) + "|"
	s += strconv.Itoa(sm.Status) + "|"
	s += sm.RedirectedURL + "|"
	s += strconv.FormatInt(sm.Created, 10) + "|"
	s += strconv.FormatInt(sm.Revalidated, 10) + "|"
	s += strconv.FormatInt(sm.Size, 10)
	return s
}

func decodeCustom(cm *StorageMetadata, bs *[]byte) error {
	splat := strings.Split(string(*bs), "|")
	if len(splat) != 9 {
		return errors.New("Bad length")
	}

	cm.Host = splat[0]
	cm.Path = splat[1]

	cm.RequestHeader = http.Header{}
	err := sToHeader(&cm.RequestHeader, &splat[2])
	if err != nil {
		return err
	}

	cm.ResponseHeader = http.Header{}
	err = sToHeader(&cm.ResponseHeader, &splat[3])
	if err != nil {
		return err
	}

	v, err := sToInt64(&splat[4])
	if err != nil {
		return err
	} else {
		cm.Status = int(v)
	}

	cm.RedirectedURL = splat[5]

	v, err = sToInt64(&splat[6])
	if err != nil {
		return err
	} else {
		cm.Created = v
	}

	v, err = sToInt64(&splat[7])
	if err != nil {
		return err
	} else {
		cm.Revalidated = v
	}

	v, err = sToInt64(&splat[8])
	if err != nil {
		return err
	} else {
		cm.Size = v
	}

	return nil
}

type StorageWriter interface {
	io.WriteCloser
	io.ReadSeeker
	http.Flusher
	WriteHeader(int, http.Header)
	ChangeKey(Key) error
	Delete() error
	WrittenFile() (*os.File, error)
}

type DiskStorage struct {
	Storage
}

func NewDiskStorage(id string, path string, size int64, logger *apexlog.Logger, now func() time.Time) Storage {
	createStoragePath(path)
	s := &storage{
		id:                    id,
		path:                  path,
		maxSizeBytes:          size,
		startedAt:             time.Now().Unix(),
		sizeBytes:             0,
		itemsChan:             make(chan *itemWithOp, 100000),
		withAccessTime:        make(map[itemName]accessedItem, 0),
		storableAccessedItems: make(map[itemName]storableAccessedItem, 0),
		withoutAccessTime:     make(map[itemName]item, 0),
		atimesPath:            filepath.Join(path, "atimes"),
		logger:                logger,
		now:                   now,
	}

	go s.runSizeLimiter()
	disablePersistentAtime := util.EnvBool("ATIME_DISABLE")
	if !disablePersistentAtime {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGABRT)
		go s.signalListener(sigChan)
		t := 30
		if sleepTime := os.Getenv("ATIME_FLUSH_INTERVAL"); len(sleepTime) > 0 {
			if it, err := strconv.Atoi(sleepTime); err == nil {
				t = it
			}
		}
		go func() {
			for {
				s.itemsChan <- &itemWithOp{op: opFlushStorable}
				time.Sleep(time.Second * time.Duration(t))
			}
		}()
	}

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
	id                    string
	path                  string
	maxSizeBytes          int64
	startedAt             int64
	sizeBytes             int64
	itemsChan             chan *itemWithOp
	withAccessTime        map[itemName]accessedItem
	withoutAccessTime     map[itemName]item
	isReplaced            bool
	atimesPath            string
	storableAccessedItems map[itemName]storableAccessedItem

	logger *apexlog.Logger
	now    func() time.Time
}

type accessedItem struct {
	accessTime    accessTime
	sizeKilobytes uint32
}

type itemOp int

const (
	opAdd itemOp = iota
	opAccessTime
	opFlushStorable
)

type itemWithOp struct {
	op                   itemOp
	name                 itemName
	accessedItem         *accessedItem
	storableAccessedItem *storableAccessedItem
}

type storableAccessedItem struct {
	accessTime    int64
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

func (s *storage) GetWriter(key Key, revalidate bool, closeNotifier *chan KeyInfo) StorageWriter {
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
			if revalidate {
				return
			}
			ai := accessedItem{
				accessTime:    accessTime(time.Now().Unix() - s.startedAt),
				sizeKilobytes: uint32(size / 1024),
			}
			s.itemsChan <- &itemWithOp{op: opAdd, name: itemName(name), accessedItem: &ai}
		}, now: func() time.Time {
			return s.now()
		}, closeNotifier: closeNotifier,
		log: s.logger}
}

const (
	metadataXAttrName = "user.rrrouter"
)

func (s *storage) Get(ctx context.Context, keys []Key) (*os.File, StorageMetadata, Key, error) {
	defer mets.FromContext(ctx).MarkTime(time.Now())
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

		sm, err := getStorageMetadata(ctx, f, metadataXAttrName)
		if err != nil {
			s.logger.Errorf("Failed to get metadata from %v: %v\n", fp, err)
			err = os.Remove(fp)
			if err != nil {
				s.logger.Errorf("Could not remove errored path %v: %v", fp, err)
				return nil, StorageMetadata{}, key, err
			}
			continue
		}
		if cl := sm.ResponseHeader.Get("content-length"); len(cl) > 0 {
			if contentLength, err := strconv.Atoi(cl); err != nil && contentLength > 0 {
				if int64(contentLength) != sm.FdSize {
					s.logger.Error(fmt.Sprintf("Size on disk %v did not match HTTP header Content-Length %v. Deleting stored file.", sm.FdSize, contentLength))
					err = os.Remove(fp)
					if err != nil {
						s.logger.Errorf("Could not remove errored path %v: %v", fp, err)
						return nil, StorageMetadata{}, key, err
					}
					continue
				}
			}
		} else if sm.FdSize != sm.Size {
			s.logger.Error(fmt.Sprintf("Size on disk %v did not match size written to client %v. Deleting stored file.", sm.FdSize, sm.Size))
			err = os.Remove(fp)
			if err != nil {
				s.logger.Errorf("Could not remove errored path %v: %v", fp, err)
				return nil, StorageMetadata{}, key, err
			}
			continue
		}

		s.setAccessTime(key, sm.Size)

		return f, sm, key, nil
	}

	return nil, StorageMetadata{}, keys[0], os.ErrNotExist
}

func getStorageMetadata(ctx context.Context, f *os.File, attrName string) (StorageMetadata, error) {
	defer mets.FromContext(ctx).MarkTime(time.Now())

	xattrb, err := xattr.FGet(f, attrName)
	if err != nil {
		return StorageMetadata{}, err
	}

	sm, err := decodeStorageMetadata(xattrb)
	if err != nil {
		return StorageMetadata{}, err
	}

	fi, err := f.Stat()
	sm.FdSize = fi.Size()

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

func (s *storage) WriteTest() (bool, error) {
	p := filepath.Join(s.path, ".healthcheck")
	err := os.Remove(p)
	if err != nil && !os.IsNotExist(err) {
		msg := "Can't remove stray .healthcheck"
		s.logger.WithError(err).Errorf(msg)
		return false, errors.New(msg)
	}
	fd, err := os.Create(p)
	if err != nil {
		msg := "Can't create .healthcheck"
		s.logger.WithError(err).Errorf(msg)
		return false, errors.New(msg)
	}
	bs := make([]byte, 1024)
	for i := 0; i < 1024; i++ {
		bs[i] = 'A'
	}
	for i := 0; i < 1024; i++ {
		n, err := fd.Write(bs)
		if err != nil || n != len(bs) {
			return false, err
		}
	}
	err = fd.Close()
	if err != nil && !os.IsNotExist(err) {
		s.logger.WithError(err).Infof("Closing .healthcheck errored")
	}
	err = os.Remove(p)
	if err != nil && !os.IsNotExist(err) {
		msg := "Removing .healthcheck errored"
		s.logger.WithError(err).Infof(msg)
		return false, errors.New(msg)
	}

	return true, nil
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
	var sizeBytes int64
	withoutAccessTime := make(map[itemName]item)

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
			sizeBytes += size
			withoutAccessTime[itemName(prefixWithItemName(name)+name)] = item{sizeKilobytes: uint32(size / 1024)}
		}
	}
	for n, i := range withoutAccessTime {
		s.withoutAccessTime[n] = i
	}
	s.sizeBytes += sizeBytes

	return fileCount
}

func (s *storage) runSizeLimiter() {
	t := time.Now()
	fileCount := s.readFiles(s.path)
	s.logger.Infof("Read sizes of %v files in %v: %v", fileCount, time.Now().Sub(t), s.sizeBytes)

	t = time.Now()
	withAccessTime, err := s.readStorableAccessTimes()
	if err != nil {
		s.logger.Infof("Errored when reading access times: %v", err)
	} else if len(withAccessTime) > 0 {
		s.logger.Infof("Read access times of %v files in %v", len(withAccessTime), time.Now().Sub(t))
		t = time.Now()
		for n, i := range withAccessTime {
			s.withAccessTime[n] = i
			delete(s.withoutAccessTime, n)
		}
		s.logger.Infof("Set access times of %v files in %v", len(withAccessTime), time.Now().Sub(t))
	}

	// Initialization done, go at it forever:

	sleepTime := time.Second * 5
	lastRun := time.Now().Add(-sleepTime)
	printChanLen := false
	for {
		if s.isReplaced {
			break
		}

		io := <-s.itemsChan
		switch io.op {
		case opAdd:
			if io.accessedItem != nil {
				s.withAccessTime[io.name] = *io.accessedItem
				s.sizeBytes += int64(io.accessedItem.sizeKilobytes * 1024)
			}
		case opAccessTime:
			if io.accessedItem != nil {
				s.withAccessTime[io.name] = *io.accessedItem
			}
			if io.storableAccessedItem != nil {
				s.storableAccessedItems[io.name] = *io.storableAccessedItem
			}
		case opFlushStorable:
			s.flushStorableAccessTimes()
		}

		if printChanLen {
			go mets.NewMetrics(nil, nil, nil).WithSampleRate(1).Mark("items channel length", len(s.itemsChan))
			printChanLen = false
		}

		if time.Now().Sub(lastRun) < sleepTime {
			continue
		}

		printChanLen = true

		s.logger.Info(s.stats())
		purgeable := purgeableItems{}
		if s.sizeBytes > s.maxSizeBytes {
			purgeable = s.purgeableItemNames(s.sizeBytes - s.maxSizeBytes)
		}
		if len(purgeable.withAccessTimes) == 0 && len(purgeable.withoutAccessTimes) == 0 {
			lastRun = time.Now()
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

		s.logger.Infof("Removed %v / %v items to release at least %v MB",
			len(removedWithoutAccessTimes)+len(removedWithAccessTimes), len(purgeable.withoutAccessTimes)+len(purgeable.withAccessTimes), purgeable.size/1024/1024)
		lastRun = time.Now()
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

func (s *storage) signalListener(c chan os.Signal) {
	for {
		sig := <-c
		switch sig {
		case syscall.SIGTERM, syscall.SIGABRT, syscall.SIGINT:
			s.logger.Infof("Received %v, running exit handlers", sig)
			if !util.EnvBool("ATIME_DISABLE") {
				s.itemsChan <- &itemWithOp{op: opFlushStorable}
				time.Sleep(time.Second)
			}
			os.Exit(0)
		}
	}
}

func (s *storage) readStorableAccessTimes() (withAccessTime map[itemName]accessedItem, err error) {
	p := s.atimesPath
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return withAccessTime, nil
		}
		s.logger.Errorf("Could not open atime file: %v", err)
		return withAccessTime, err
	}
	defer f.Close()

	withAccessTime = make(map[itemName]accessedItem, 0)
	reader := bufio.NewReader(f)
	var l string
	for {
		l, err = reader.ReadString('\n')
		if err != nil {
			break
		}
		if len(l) > 0 {
			l = l[:len(l)-1]
		}
		parts := strings.Split(l, "|")
		if len(parts) != 3 {
			continue
		}
		name := parts[0]
		var atime uint32
		var size uint32
		satime := parts[1]
		i64, err := strconv.ParseInt(satime, 10, 64)
		if err != nil {
			continue
		}
		atime = uint32(s.startedAt - i64)
		ssize := parts[2]
		v, err := strconv.Atoi(ssize)
		if err != nil {
			continue
		}
		size = uint32(v)
		withAccessTime[itemName(name)] = accessedItem{accessTime: accessTime(atime), sizeKilobytes: size}
	}
	if err != io.EOF {
		s.logger.Warnf("Reading access times failed with %v items read: %v", len(withAccessTime), err)
	}

	return withAccessTime, nil
}

func (s *storage) resetStorableAccessTimes() {
	s.storableAccessedItems = make(map[itemName]storableAccessedItem, 0)
}

func (s *storage) flushStorableAccessTimes() {
	defer s.resetStorableAccessTimes()

	if len(s.storableAccessedItems) == 0 {
		return
	}

	buf := new(bytes.Buffer)
	p := s.atimesPath
	tp := filepath.Join(s.path, "atimes-truncated")
	// Roughly 60 bytes per item, times 3M, is about 171MB on disk and takes roughly two seconds to parse into memory
	// on startup on a 2016 laptop.
	maxLength := int64(60 * 3000000)
	if as := os.Getenv("ATIME_LOG_SIZE_BYTES"); len(as) > 0 {
		if l, err := strconv.Atoi(as); err == nil {
			maxLength = int64(l)
		}
	}

	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		if !os.IsNotExist(err) {
			s.logger.Errorf("atime file opening errored: %v", err)
			err := os.Remove(p)
			if err != nil {
				s.logger.Errorf("Could not remove errored file: %v", err)
			}
		}
		f, err = os.Create(p)
		if err != nil {
			s.logger.Errorf("Could not create atime file: %v", err)
			return
		}
	}
	defer f.Close()
	length, err := f.Seek(0, 2)
	if err != nil {
		s.logger.Errorf("Could not seek to end of atime file: %v", err)
		return
	}

	step := func() error {
		if buf.Len() > 0 {
			_, werr := f.Write(buf.Bytes())
			if werr != nil {
				s.logger.WithField("error", werr).Infof("Writing atime errored")
				return werr
			}
		}
		buf.Reset()
		return nil
	}
	delim := byte('\n')
	n := 0

	for name, item := range s.storableAccessedItems {
		if n%1000 == 0 {
			err := step()
			if err != nil {
				err = f.Close()
				if err != nil {
					s.logger.Errorf("Could not close atime file after error: %v", err)
					return
				}
			}
		}
		s := string(name) + "|" + strconv.FormatInt(item.accessTime, 10) + "|" + strconv.Itoa(int(item.sizeKilobytes))
		buf.Write([]byte(s))
		buf.WriteByte(delim)
		n += 1
	}
	err = step()
	if err != nil {
		s.logger.Errorf("Writing atime errored: %v", err)
	}

	if length > maxLength {
		bytesToTrim := length - maxLength + (maxLength / 10) // Chop 10% off the top.
		s.logger.Infof("Trimming %v from %v", bytesToTrim, length)
		seekPos, err := f.Seek(bytesToTrim, 0)
		if err != nil {
			s.logger.Errorf("Could not seek in atime file: %v", err)
			return
		}
		b := make([]byte, 4*1024)
		n, err = f.Read(b)
		if err != nil && err != io.EOF {
			s.logger.Errorf("Could not read atime file: %v", err)
			return
		}
		delimPos := int64(bytes.IndexByte(b, delim))
		if delimPos == -1 {
			s.logger.Errorf("Delimiter not found in atimes: %v", err)
			return
		}
		_, err = f.Seek(seekPos+delimPos+1, 0)
		if err != nil {
			s.logger.Errorf("Could not seek to prune position of atime file: %v", err)
			return
		}
		outfd, err := os.Create(tp)
		if err != nil {
			os.Remove(tp)
			outfd, err = os.Create(tp)
			if err != nil {
				s.logger.Errorf("Could not create truncated file: %v", err)
				return
			}
		}
		defer outfd.Close()

		b = make([]byte, 64*1024)
		var rerr error
		var werr error
		var rn int
		for rn, rerr = f.Read(b); rerr == nil; {
			n, werr = outfd.Write(b[:rn])
			if werr != nil {
				s.logger.Errorf("Could not write to truncated file: %v", err)
				return
			}
			rn, rerr = f.Read(b)
		}
		if rerr != io.EOF {
			s.logger.Errorf("Could not read from original atime file: %v", err)
			return
		}

		err = outfd.Close()
		if err != nil {
			s.logger.Errorf("Could not close truncated file: %v", err)
			return
		}
		err = f.Close()
		if err != nil {
			s.logger.Errorf("Could not close old atime file: %v", err)
		}
		err = os.Remove(p)
		if err != nil {
			s.logger.Errorf("Could not remove old atime file: %v", err)
		}
		err = os.Rename(tp, p)
		if err != nil {
			s.logger.Errorf("Could not rename new atime file: %v", err)
		}
	}
}

func (s *storage) setAccessTime(key Key, size int64) {
	name := itemName(key.FsName())
	item := accessedItem{accessTime(time.Now().Unix() - s.startedAt), uint32(size / 1024)}
	storableItem := storableAccessedItem{time.Now().Unix(), uint32(size / 1024)}
	s.itemsChan <- &itemWithOp{op: opAccessTime, name: name, accessedItem: &item, storableAccessedItem: &storableItem}
}

type storageWriter struct {
	key               Key
	oldKey            *Key
	root              string
	path              string
	invalidated       bool
	error             error
	deleted           bool
	closeFinisher     func(name string, size int64)
	closeNotifier     *chan KeyInfo
	closed            bool
	fd                *os.File
	writtenStatus     int
	responseHeader    http.Header
	redirectedURL     *url.URL
	created           int64
	writtenSize       int64
	log               *apexlog.Logger
	wasRevalidated    bool
	revalidateErrored bool
	canStaleIfError   bool
	now               func() time.Time
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
			sw.error = err
			sw.notify()
			return
		}
		var fd *os.File
		fd, exists, err := createIfNotExists(sw.path)
		if exists {
			//sw.log.Infof("File already exists for key %v: %v", sw.key, sw.path)
			fd, err = os.OpenFile(sw.path, os.O_RDWR, 0)
			if err != nil {
				sw.log.Errorf("Can't open existing file for reading and writing: %v", sw.path)
				sw.error = err
				sw.notify()
				return
			}
		}
		sw.fd = fd
	}
}

func createIfNotExists(name string) (*os.File, bool, error) {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			var fd *os.File
			fd, err = os.Create(name)
			if err != nil {
				return nil, false, err
			}
			return fd, false, nil
		} else {
			return nil, false, err
		}
	}

	return nil, true, nil
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
	} else if sw.error != nil {
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
	} else if sw.error != nil {
		sw.Delete()
		return errors.New("Close called for errored writer")
	} else if sw.revalidateErrored {
		sw.finishAndNotify()
		return nil
	}

	var revalidatedMetadata *StorageMetadata
	if sw.fd == nil {
		if sw.wasRevalidated {
			fd, err := os.OpenFile(sw.path, os.O_RDWR, 0)
			if err != nil {
				sw.log.Errorf("Could not reopen file %v for revalidation state saving: %v", sw.path, err)
				sw.Delete()
				return err
			}
			sm, err := getStorageMetadata(nil, fd, metadataXAttrName)
			if err != nil {
				sw.Delete()
				return err
			}
			sm.Revalidated = sw.now().Unix()
			revalidatedMetadata = &sm
			sw.fd = fd
		} else {
			return nil
		}
	}

	fi, err := sw.fd.Stat()
	if err != nil {
		sw.log.Errorf("Could not stat file %v: %v", sw.fd.Name(), err)
		sw.Delete()
		return err
	}
	sizeOnDisk := fi.Size()

	err = sw.fd.Close()
	if err != nil {
		sw.Delete()
		return err
	}

	if sw.invalidated {
		err = sw.Delete()
		if err != nil {
			sw.log.Warnf("Could not remove invalidated file %v: %v", sw.path, err)
		}
		return err
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

	if cl := sw.responseHeader.Get("content-length"); len(cl) > 0 {
		if contentLength, err := strconv.Atoi(cl); err != nil && contentLength > 0 {
			if int64(contentLength) != sw.writtenSize || int64(contentLength) != sizeOnDisk {
				sw.log.Error(fmt.Sprintf("Written size %v did not match Content-Length header size %v. Deleting stored file.\n", sw.writtenSize, contentLength))
				sw.Delete()
				return errors.New(fmt.Sprintf("Size mismatch"))
			}
		}
	} else {
		if sizeOnDisk != metadata.Size {
			sw.log.Errorf("Size has changed for file %v: %v vs. %v. wasRevalidated: %v", sw.fd.Name(), sizeOnDisk, metadata.Size, sw.wasRevalidated)
			sw.Delete()
			return errors.New("Size mismatch")
		}
	}

	if sw.key.method != "HEAD" && sizeOnDisk == 0 && sw.writtenStatus != 204 && !util.IsRedirect(sw.writtenStatus) {
		msg := fmt.Sprintf("Size is 0. Deleting stored file")
		sw.log.Errorf(msg)
		sentry.WithScope(func(s *sentry.Scope) {
			s.SetContext("locals", map[string]interface{}{
				"url":                  sw.key.host + sw.key.path,
				"method":               sw.key.method,
				"ua":                   sw.key.originalHeaders.Get("user-agent"),
				"sw.key.storedHeaders": fmt.Sprint(sw.key.storedHeaders),
				"sw.writtenStatus":     sw.writtenStatus,
				"sw.writtenSize":       sw.writtenSize,
				"sw.wasRevalidated":    sw.wasRevalidated,
				"sw.responseHeader":    fmt.Sprint(sw.responseHeader),
			})
			sentry.CaptureMessage(msg)
		})
		sw.Delete()
		return errors.New("Size mismatch")
	}

	esm := encodeStorageMetadata(metadata)
	err = xattr.Set(sw.path, metadataXAttrName, esm)
	if err != nil {
		sw.Delete()
		return err
	}

	sw.finishAndNotify()
	sw.closed = true

	return err
}

func (sw *storageWriter) finishAndNotify() {
	if sw.closeFinisher != nil {
		sw.closeFinisher(sw.key.FsName(), sw.writtenSize)
	}

	sw.notify()
}

func (sw *storageWriter) notify() {
	canUseStale := false
	if sw.revalidateErrored && sw.canStaleIfError {
		canUseStale = true
	}
	if sw.closeNotifier != nil {
		*sw.closeNotifier <- KeyInfo{Key: sw.key, CanUseStale: canUseStale}
		if sw.oldKey != nil {
			sw.log.Debugf("Had old Key: %v", *sw.oldKey)
			*sw.closeNotifier <- KeyInfo{Key: *sw.oldKey, CanUseStale: canUseStale}
		}
	}
}

func (sw *storageWriter) WrittenFile() (*os.File, error) {
	if sw.invalidated {
		return nil, nil
	} else if sw.error != nil {
		return nil, sw.error
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

func (sw *storageWriter) SetRevalidateErrored(canStaleIfError bool) {
	sw.revalidateErrored = true
	sw.canStaleIfError = canStaleIfError
}

func (sw *storageWriter) Delete() error {
	if sw.deleted {
		return nil
	}

	closeErr := sw.fd.Close()
	err := os.Remove(sw.path)
	if err != nil && !os.IsNotExist(err) {
		sw.log.Errorf("Could not remove path %v: %v. Close error was: %v", sw.path, err, closeErr)
		return err
	}

	sw.deleted = true

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
