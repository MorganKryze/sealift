package service

import (
	"bytes"
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
	Op, Bucket, Key, Prefix string
	Max                     int
}

// fakeMinio is an Objects in memory, one object map per bucket, with every call recorded.
type fakeMinio struct {
	mu      sync.Mutex
	buckets map[string]map[string]s3.Object
	calls   []call
	// failWith, when set, is returned by every call.
	failWith error
}

func newFakeMinio() *fakeMinio { return &fakeMinio{buckets: map[string]map[string]s3.Object{}} }

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

func (f *fakeMinio) Get(_ context.Context, bucket, key, _ string) (io.ReadCloser, s3.Object, error) {
	if err := f.record(call{Op: "get", Bucket: bucket, Key: key}); err != nil {
		return nil, s3.Object{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if o, ok := f.buckets[bucket][key]; ok {
		return io.NopCloser(bytes.NewReader(make([]byte, o.Size))), o, nil
	}
	return nil, s3.Object{}, s3.ErrNotFound
}

func (f *fakeMinio) Delete(_ context.Context, bucket, key string) error {
	if err := f.record(call{Op: "delete", Bucket: bucket, Key: key}); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.buckets[bucket], key)
	return nil
}
