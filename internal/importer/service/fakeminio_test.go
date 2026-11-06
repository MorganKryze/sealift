package service

import (
	"context"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MorganKryze/sealift/internal/importer/s3"
)

// call is one request the fake received.
type call struct {
	Op, Bucket, Key, Prefix, ETag string
	Max                           int
}

// fakeMinio is an Objects in memory, one object map per bucket, with every call recorded.
type fakeMinio struct {
	mu      sync.Mutex
	buckets map[string]map[string]s3.Object
	calls   []call
	// failWith, when set, is returned by every call.
	failWith error
	// data holds the bytes of an object put with putData; put keeps zeros.
	data map[string][]byte
	// cut makes a read of the keyed object end cleanly after that many bytes.
	cut map[string]int
	// stall makes a read of the keyed object block after that many bytes until its context ends.
	stall map[string]int
	// readErr makes a read of the keyed object fail after cut bytes.
	readErr map[string]error
	// serveETag, when set for a key, is the ETag a Get answers whatever the request asked.
	serveETag map[string]string
	// failDelete makes a delete of the keyed object fail, whatever the bucket.
	failDelete map[string]error
	// hook, when set, runs at the start of every Head and Get, before the fake looks at its objects.
	hook func(op, key string)
	// stalled receives a value each time a read starts to block.
	stalled chan struct{}
}

func newFakeMinio() *fakeMinio {
	return &fakeMinio{
		buckets: map[string]map[string]s3.Object{}, data: map[string][]byte{}, cut: map[string]int{},
		stall: map[string]int{}, stalled: make(chan struct{}, 8), readErr: map[string]error{}, serveETag: map[string]string{}, failDelete: map[string]error{},
	}
}

func dataKey(bucket, key string) string { return bucket + "/" + key }

// putData stores an object of alice's that holds b.
func (f *fakeMinio) putData(key string, b []byte) {
	f.put(bucketAlice, key, int64(len(b)))
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[dataKey(bucketAlice, key)] = b
}

// change gives alice's object a new ETag, as a replaced object has.
func (f *fakeMinio) change(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.buckets[bucketAlice][key]
	o.ETag = `"changed-` + key + `"`
	f.buckets[bucketAlice][key] = o
}

// vanish removes alice's object without a recorded call, as another client's delete would.
func (f *fakeMinio) vanish(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.buckets[bucketAlice], key)
}

// etagOf returns the current ETag of alice's object.
func (f *fakeMinio) etagOf(key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.buckets[bucketAlice][key].ETag
}

var epoch = time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)

// put stores an object of the given size in a bucket, creating the bucket.
func (f *fakeMinio) put(bucket, key string, size int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.buckets[bucket] == nil {
		f.buckets[bucket] = map[string]s3.Object{}
	}
	f.buckets[bucket][key] = s3.Object{Key: key, ETag: `"etag-` + key + `"`, Size: size, LastModified: epoch}
}

func (f *fakeMinio) record(c call) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
	return f.failWith
}

func (f *fakeMinio) recorded() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]call(nil), f.calls...)
}

func (f *fakeMinio) List(_ context.Context, bucket, prefix string, limit int) (s3.Listing, error) {
	if err := f.record(call{Op: "list", Bucket: bucket, Prefix: prefix, Max: limit}); err != nil {
		return s3.Listing{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	objs, ok := f.buckets[bucket]
	if !ok {
		return s3.Listing{}, &s3.Error{Status: 404, Code: "NoSuchBucket", Message: "The specified bucket does not exist"}
	}
	var keys []string
	for k := range objs {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := s3.Listing{Objects: []s3.Object{}}
	for _, k := range keys {
		if len(out.Objects) == limit {
			out.Truncated = true
			break
		}
		out.Objects = append(out.Objects, objs[k])
	}
	return out, nil
}

func (f *fakeMinio) Head(_ context.Context, bucket, key string) (s3.Object, error) {
	f.mu.Lock()
	hook := f.hook
	f.mu.Unlock()
	if hook != nil {
		hook("head", key)
	}
	if err := f.record(call{Op: "head", Bucket: bucket, Key: key}); err != nil {
		return s3.Object{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if o, ok := f.buckets[bucket][key]; ok {
		return o, nil
	}
	return s3.Object{}, s3.ErrNotFound
}

func (f *fakeMinio) Get(ctx context.Context, bucket, key, etag string) (io.ReadCloser, s3.Object, error) {
	f.mu.Lock()
	hook := f.hook
	f.mu.Unlock()
	if hook != nil {
		hook("get", key)
	}
	if err := f.record(call{Op: "get", Bucket: bucket, Key: key, ETag: etag}); err != nil {
		return nil, s3.Object{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.buckets[bucket][key]
	if !ok {
		return nil, s3.Object{}, s3.ErrNotFound
	}
	if etag != "" && o.ETag != etag {
		return nil, s3.Object{}, s3.ErrChanged
	}
	dk := dataKey(bucket, key)
	b, ok := f.data[dk]
	if !ok {
		b = make([]byte, o.Size)
	}
	if e, ok := f.serveETag[dk]; ok {
		o.ETag = e
	}
	body := &fakeBody{ctx: ctx, data: b, stallAt: -1, stalled: f.stalled}
	if n, ok := f.cut[dk]; ok {
		body.data = b[:n]
	}
	if n, ok := f.stall[dk]; ok {
		body.data, body.stallAt = b[:n], n
	}
	if err, ok := f.readErr[dk]; ok {
		body.err = err
	}
	return body, o, nil
}

// fakeBody serves data, then ends with err, blocks until ctx ends (stallAt >= 0), or ends cleanly.
type fakeBody struct {
	ctx     context.Context
	data    []byte
	stallAt int
	stalled chan<- struct{}
	err     error
}

func (b *fakeBody) Read(p []byte) (int, error) {
	if len(b.data) > 0 {
		n := copy(p, b.data)
		b.data = b.data[n:]
		return n, nil
	}
	switch {
	case b.stallAt >= 0:
		select {
		case b.stalled <- struct{}{}:
		default:
		}
		<-b.ctx.Done()
		return 0, b.ctx.Err()
	case b.err != nil:
		return 0, b.err
	}
	return 0, io.EOF
}

func (b *fakeBody) Close() error { return nil }

func (f *fakeMinio) Delete(_ context.Context, bucket, key string) error {
	if err := f.record(call{Op: "delete", Bucket: bucket, Key: key}); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.failDelete[key]; ok {
		return err
	}
	delete(f.buckets[bucket], key)
	return nil
}
