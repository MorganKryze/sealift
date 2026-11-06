package service

import (
	"context"
	"errors"
	"io"
	"net/url"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/MorganKryze/sealift/internal/importer/s3"
)

const (
	// Folder is the only part of a user's bucket the service lists, reads or deletes.
	Folder = "packages/npm/"
	// MaxListed is how many objects one list reads: one MinIO page of 1,000 keys.
	MaxListed = 1000

	archiveSuffix = ".tar.gz"
	manifestName  = "manifest.json"
	// maxKeyBytes is S3's limit on an object key: 1,024 bytes.
	maxKeyBytes = 1024
	// maxTextChars caps text from MinIO that reaches an answer: 300 characters.
	maxTextChars = 300
	// maxFolderDepth is how many folders may sit between Folder and an archive.
	maxFolderDepth = 1

	reasonName       = "its name cannot be imported"
	reasonSeveral    = "the folder holds more than one archive"
	reasonNoManifest = "no manifest.json in its folder"
)

// Objects is the MinIO the service reads. It lists, heads, reads and deletes; it never writes.
type Objects interface {
	List(ctx context.Context, bucket, prefix string, limit int) (s3.Listing, error)
	Head(ctx context.Context, bucket, key string) (s3.Object, error)
	Get(ctx context.Context, bucket, key, etag string) (io.ReadCloser, s3.Object, error)
	Delete(ctx context.Context, bucket, key string) error
}

// bucketOf names a user's bucket. It takes the checked user and nothing from the request.
func bucketOf(user string) string { return "user-" + user }

// ArchiveKey returns nil when key may be imported: under Folder, ending in
// .tar.gz, at most one folder below, with no empty, "." or ".." segment. The
// reason names the rule and never repeats the key.
func ArchiveKey(key string) error {
	switch {
	case len(key) > maxKeyBytes:
		return errors.New("the key is over 1024 bytes")
	case !utf8.ValidString(key):
		return errors.New("the key is not valid UTF-8")
	case strings.IndexFunc(key, unicode.IsControl) >= 0:
		return errors.New("the key holds a control character")
	case !strings.HasPrefix(key, Folder):
		return errors.New("the key must start with " + Folder)
	case !strings.HasSuffix(key, archiveSuffix):
		return errors.New("the key must end with " + archiveSuffix)
	}
	if err := checkSegments(key); err != nil {
		return err
	}
	// A gateway or a proxy may decode the key once more, so the decoded form
	// must pass too. An escape that does not decode is a plain name.
	if decoded, err := url.PathUnescape(key); err == nil && decoded != key {
		if !strings.HasPrefix(decoded, Folder) {
			return errors.New("the key must start with " + Folder + " once decoded")
		}
		return checkSegments(decoded)
	}
	return nil
}

func checkSegments(key string) error {
	segments := strings.Split(strings.TrimPrefix(key, Folder), "/")
	for _, s := range segments {
		if s == "" || s == "." || s == ".." {
			return errors.New(`the key holds an empty, "." or ".." segment`)
		}
	}
	if len(segments) > maxFolderDepth+1 {
		return errors.New("the key may sit at most one folder below " + Folder)
	}
	return nil
}

// cleanText drops invalid UTF-8 and control characters, then cuts to maxTextChars.
func cleanText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	if r := []rune(s); len(r) > maxTextChars {
		s = string(r[:maxTextChars])
	}
	return s
}

// folderOf splits a key under Folder into its folder ("" for the root) and
// file name. ok is false for an object more than one folder down.
func folderOf(key string) (folder, name string, ok bool) {
	rel := strings.TrimPrefix(key, Folder)
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		folder, name = rel[:i], rel[i+1:]
	} else {
		name = rel
	}
	depth := 0
	for _, seg := range strings.Split(folder, "/") {
		if seg != "" {
			depth++
		}
	}
	return folder, name, depth <= maxFolderDepth
}

// pair turns a listing into archives, each matched with the manifest.json of
// its own folder. Other objects, and anything deeper than one folder, are ignored.
func pair(objects []s3.Object) []Archive {
	type folder struct {
		archives []s3.Object
		manifest bool
	}
	folders := map[string]*folder{}
	at := func(name string) *folder {
		if folders[name] == nil {
			folders[name] = &folder{}
		}
		return folders[name]
	}
	for _, o := range objects {
		dir, name, ok := folderOf(o.Key)
		switch {
		case !ok || !strings.HasPrefix(o.Key, Folder):
		case name == manifestName:
			at(dir).manifest = true
		case strings.HasSuffix(name, archiveSuffix):
			f := at(dir)
			f.archives = append(f.archives, o)
		}
	}
	out := []Archive{}
	for _, f := range folders {
		for _, o := range f.archives {
			a := Archive{Key: o.Key, Size: o.Size, Modified: o.LastModified, Importable: true}
			var reason string
			switch {
			case ArchiveKey(o.Key) != nil:
				a.Key, reason = cleanText(o.Key), reasonName
			case len(f.archives) > 1:
				reason = reasonSeveral
			case !f.manifest:
				reason = reasonNoManifest
			}
			if reason != "" {
				a.Importable, a.Reason = false, &reason
			}
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// ListArchives lists the archives in the user's own folder: the bucket comes
// from the checked user and the prefix is Folder, whatever the request carries.
func (h *Handlers) ListArchives(ctx context.Context, _ ListArchivesRequestObject) (ListArchivesResponseObject, error) {
	user := userFrom(ctx)
	out := ArchiveList{
		MinioConfigured: h.objects != nil, Bucket: bucketOf(user), Folder: Folder,
		Unencrypted: append([]string{}, h.links...), Archives: []Archive{},
	}
	if h.objects == nil {
		return ListArchives200JSONResponse(out), nil
	}
	lctx, cancel := context.WithTimeout(ctx, minioCallTimeout)
	defer cancel()
	listing, err := h.objects.List(lctx, out.Bucket, Folder, MaxListed)
	switch {
	case s3.IsNoBucket(err):
		msg := "MinIO has no bucket " + out.Bucket + " yet: nothing to list"
		out.BucketMissing, out.Message = true, &msg
		return ListArchives200JSONResponse(out), nil
	case err != nil:
		h.log.Warn("could not list a user's archives", "bucket", out.Bucket, "error", cleanText(err.Error()))
		detail := cleanText("MinIO could not list the archives: " + err.Error())
		return ListArchivesdefaultApplicationProblemPlusJSONResponse{
			StatusCode: 502,
			Body:       Problem{Type: ptr("about:blank"), Title: "MinIO failed", Status: 502, Detail: &detail},
		}, nil
	}
	out.Truncated = listing.Truncated
	out.Archives = pair(listing.Objects)
	h.addLatestImports(user, out.Archives, listing.Objects)
	return ListArchives200JSONResponse(out), nil
}

// addLatestImports gives each archive the id and outcome of its user's newest
// import of the objects now in MinIO: the same archive and manifest keys with
// the same ETags. Folders reuse their names from one export to the next, so an
// import of an earlier upload must not stand for this one. A store that cannot
// be read leaves the list as it is.
func (h *Handlers) addLatestImports(user string, archives []Archive, listed []s3.Object) {
	if h.store == nil {
		return
	}
	imps, err := h.store.List(user)
	if err != nil {
		h.log.Warn("could not read the imports for the archive list", "error", cleanText(err.Error()))
		return
	}
	etags := make(map[string]string, len(listed))
	for _, o := range listed {
		etags[o.Key] = o.ETag
	}
	type objects struct{ archive, manifest, key string }
	latest := map[objects]LatestImport{}
	for i := len(imps) - 1; i >= 0; i-- { // oldest first, so the newest wins
		imp := imps[i]
		at := objects{imp.Archive.ETag, imp.Manifest.ETag, imp.Archive.Key}
		latest[at] = LatestImport{Id: imp.ID, Outcome: imp.Outcome()}
	}
	for i := range archives {
		key := archives[i].Key
		at := objects{etags[key], etags[path.Dir(key)+"/"+manifestName], key}
		if li, ok := latest[at]; ok {
			archives[i].LatestImport = &li
		}
	}
}
