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

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/importer/s3"
)

const (
	// FolderNPM holds npm archives. With FolderPip, it is the only part of a
	// user's bucket the service lists, reads or deletes.
	FolderNPM = "packages/npm/"
	// FolderPip holds pip archives.
	FolderPip = "packages/pip/"
	// MaxListed is how many objects one list of a folder reads: one MinIO page of 1,000 keys.
	MaxListed = 1000
	// maxMarkReads is how many manifests one list reads for the folder mark: 50.
	maxMarkReads = 50
	// maxMarks is how many manifest ETags the mark cache keeps: 4,096.
	maxMarks = 4096

	archiveSuffix = ".tar.gz"
	manifestName  = "manifest.json"
	signatureName = archive.SignatureFile
	// maxKeyBytes is S3's limit on an object key: 1,024 bytes.
	maxKeyBytes = 1024
	// maxTextChars caps text from MinIO that reaches an answer: 300 characters.
	maxTextChars = 300
	// maxFolderDepth is how many folders may sit between a folder and an archive.
	maxFolderDepth = 1

	reasonName        = "its name cannot be imported"
	reasonSeveral     = "the folder holds more than one archive"
	reasonNoManifest  = "no manifest.json in its folder"
	reasonNoSignature = "no " + signatureName + " in its folder"
)

// Objects is the MinIO the service reads. It lists, heads, reads and deletes; it never writes.
type Objects interface {
	List(ctx context.Context, bucket, prefix string, limit int) (s3.Listing, error)
	Head(ctx context.Context, bucket, key string) (s3.Object, error)
	Get(ctx context.Context, bucket, key, etag string) (io.ReadCloser, s3.Object, error)
	Delete(ctx context.Context, bucket, key string) error
}

// folders are the folders a list covers, npm first.
var folders = []struct {
	prefix    string
	ecosystem archive.Ecosystem
}{{FolderNPM, archive.NPM}, {FolderPip, archive.Pip}}

// FolderOf returns the ecosystem of the folder that holds key.
func FolderOf(key string) (archive.Ecosystem, bool) {
	for _, f := range folders {
		if strings.HasPrefix(key, f.prefix) {
			return f.ecosystem, true
		}
	}
	return "", false
}

// folderFor is the folder that takes archives of eco.
func folderFor(eco archive.Ecosystem) string {
	for _, f := range folders {
		if f.ecosystem == eco {
			return f.prefix
		}
	}
	return ""
}

// bucketOf names a user's bucket. It takes the checked user and nothing from the request.
func bucketOf(user string) string { return "user-" + user }

// ArchiveKey returns nil when key may be imported: under one of the two
// folders, and still under the same folder once decoded. It ends in .tar.gz,
// sits at most one folder below, and holds no empty, "." or ".." segment. The
// reason names the rule and never repeats the key.
func ArchiveKey(key string) error {
	eco, _ := FolderOf(key)
	folder := folderFor(eco)
	switch {
	case len(key) > maxKeyBytes:
		return errors.New("the key is over 1024 bytes")
	case !utf8.ValidString(key):
		return errors.New("the key is not valid UTF-8")
	case strings.IndexFunc(key, unicode.IsControl) >= 0:
		return errors.New("the key holds a control character")
	case folder == "":
		return errors.New("the key must start with " + FolderNPM + " or " + FolderPip)
	case !strings.HasSuffix(key, archiveSuffix):
		return errors.New("the key must end with " + archiveSuffix)
	}
	if err := checkSegments(key, folder); err != nil {
		return err
	}
	// A gateway or a proxy may decode the key once more, so the decoded form
	// must pass too, under the same folder. An escape that does not decode is a plain name.
	if decoded, err := url.PathUnescape(key); err == nil && decoded != key {
		if !strings.HasPrefix(decoded, folder) {
			return errors.New("the key must stay under " + folder + " once decoded")
		}
		return checkSegments(decoded, folder)
	}
	return nil
}

func checkSegments(key, folder string) error {
	segments := strings.Split(strings.TrimPrefix(key, folder), "/")
	for _, s := range segments {
		if s == "" || s == "." || s == ".." {
			return errors.New(`the key holds an empty, "." or ".." segment`)
		}
	}
	if len(segments) > maxFolderDepth+1 {
		return errors.New("the key may sit at most one folder below " + folder)
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

// folderOf splits a key under prefix into its folder ("" for the root) and
// file name. ok is false for an object more than one folder down.
func folderOf(key, prefix string) (folder, name string, ok bool) {
	rel := strings.TrimPrefix(key, prefix)
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

// pair turns a listing of prefix into archives of eco, each matched with the
// manifest.json and the manifest.json.sig of its own folder. Objects outside
// prefix, other objects, and anything deeper than one folder are ignored.
func pair(objects []s3.Object, prefix string, eco archive.Ecosystem) []Archive {
	type folder struct {
		archives  []s3.Object
		manifest  bool
		signature bool
	}
	byDir := map[string]*folder{}
	at := func(name string) *folder {
		if byDir[name] == nil {
			byDir[name] = &folder{}
		}
		return byDir[name]
	}
	for _, o := range objects {
		dir, name, ok := folderOf(o.Key, prefix)
		switch {
		case !ok || !strings.HasPrefix(o.Key, prefix):
		case name == manifestName:
			at(dir).manifest = true
		case name == signatureName:
			at(dir).signature = true
		case strings.HasSuffix(name, archiveSuffix):
			f := at(dir)
			f.archives = append(f.archives, o)
		}
	}
	out := []Archive{}
	for _, f := range byDir {
		for _, o := range f.archives {
			a := Archive{Key: o.Key, Ecosystem: ptr(Ecosystem(eco)), Size: o.Size, Modified: o.LastModified, Importable: true}
			var reason string
			switch {
			case ArchiveKey(o.Key) != nil:
				a.Key, reason = cleanText(o.Key), reasonName
			case len(f.archives) > 1:
				reason = reasonSeveral
			case !f.manifest:
				reason = reasonNoManifest
			case !f.signature:
				reason = reasonNoSignature
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

// ListArchives lists the archives in the user's own folders: the bucket comes
// from the checked user and the prefixes are FolderNPM and FolderPip, whatever
// the request carries. A folder MinIO cannot list is named in the message
// while the other is listed; the answer is 502 only when both fail.
func (h *Handlers) ListArchives(ctx context.Context, _ ListArchivesRequestObject) (ListArchivesResponseObject, error) {
	user := userFrom(ctx)
	names := make([]string, len(folders))
	for i, f := range folders {
		names[i] = f.prefix
	}
	out := ArchiveList{
		MinioConfigured: h.objects != nil, Bucket: bucketOf(user), Folder: FolderNPM, Folders: &names,
		Unencrypted: append([]string{}, h.links...), Archives: []Archive{},
	}
	if h.objects == nil {
		return ListArchives200JSONResponse(out), nil
	}
	lctx, cancel := context.WithTimeout(ctx, minioCallTimeout)
	defer cancel()
	var listed []s3.Object
	var failures []string
	var lastErr error
	noBucket := false
	for _, f := range folders {
		listing, err := h.objects.List(lctx, out.Bucket, f.prefix, MaxListed)
		if err != nil {
			noBucket = noBucket || s3.IsNoBucket(err)
			h.log.Warn("could not list a user's archives", "bucket", out.Bucket, "folder", f.prefix, "error", cleanText(err.Error()))
			failures = append(failures, cleanText("MinIO could not list "+f.prefix+": "+err.Error()))
			lastErr = err
			continue
		}
		out.Truncated = out.Truncated || listing.Truncated
		listed = append(listed, listing.Objects...)
		out.Archives = append(out.Archives, pair(listing.Objects, f.prefix, f.ecosystem)...)
	}
	switch {
	case len(failures) == len(folders) && noBucket:
		msg := "MinIO has no bucket " + out.Bucket + " yet: nothing to list"
		out.BucketMissing, out.Message = true, &msg
		return ListArchives200JSONResponse(out), nil
	case len(failures) == len(folders):
		detail := cleanText("MinIO could not list the archives: " + lastErr.Error())
		return ListArchivesdefaultApplicationProblemPlusJSONResponse{
			StatusCode: 502,
			Body:       Problem{Type: ptr("about:blank"), Title: "MinIO failed", Status: 502, Detail: &detail},
		}, nil
	case len(failures) > 0:
		out.Message = &failures[0]
	}
	sort.Slice(out.Archives, func(i, j int) bool { return out.Archives[i].Key < out.Archives[j].Key })
	h.markFolders(lctx, out.Bucket, out.Archives, listed)
	h.addLatestImports(user, out.Archives, listed)
	return ListArchives200JSONResponse(out), nil
}

// markFolders marks an importable archive whose manifest describes the other
// ecosystem. It reads at most maxMarkReads manifests it has not read before,
// each with its listed ETag and within archive.MaxManifestSize. The mark is
// advisory: a manifest it cannot read or parse leaves the row as it is, and
// the attempt checks the ecosystem again after the signature.
func (h *Handlers) markFolders(ctx context.Context, bucket string, archives []Archive, listed []s3.Object) {
	manifests := make(map[string]s3.Object, len(listed))
	for _, o := range listed {
		manifests[o.Key] = o
	}
	reads := 0
	for i := range archives {
		a := &archives[i]
		folder, ok := FolderOf(a.Key)
		m, found := manifests[path.Dir(a.Key)+"/"+manifestName]
		if !a.Importable || !ok || !found || m.Size > archive.MaxManifestSize || !validETag(m.ETag) {
			continue
		}
		eco, known := h.recall(m.ETag)
		if !known {
			if reads == maxMarkReads {
				continue
			}
			reads++
			var err error
			if eco, err = h.readEcosystem(ctx, bucket, m); err != nil {
				continue
			}
			h.remember(m.ETag, eco)
		}
		if eco != "" && eco != folder {
			reason := "its manifest is " + article(eco) + " " + string(eco) + " archive's: keep the three files under " + folderFor(eco)
			a.Importable, a.Reason = false, &reason
		}
	}
}

func article(eco archive.Ecosystem) string {
	if eco == archive.NPM {
		return "an"
	}
	return "a"
}

// readEcosystem reads a manifest's ecosystem. An error is a read that failed
// and may pass later; a manifest that does not parse gives "" and no error,
// since the same ETag holds the same bytes.
func (h *Handlers) readEcosystem(ctx context.Context, bucket string, m s3.Object) (archive.Ecosystem, error) {
	body, _, err := h.objects.Get(ctx, bucket, m.Key, m.ETag)
	if err != nil {
		return "", err
	}
	defer body.Close()
	data, err := archive.ReadManifest(body)
	var ref *archive.Refusal
	switch {
	case errors.As(err, &ref):
		return "", nil
	case err != nil:
		return "", err
	}
	eco, err := archive.ManifestEcosystem(data)
	if err != nil {
		return "", nil
	}
	return eco, nil
}

// recall returns the ecosystem remembered for a manifest's ETag.
func (h *Handlers) recall(etag string) (archive.Ecosystem, bool) {
	h.marksMu.Lock()
	defer h.marksMu.Unlock()
	eco, ok := h.marks[etag]
	return eco, ok
}

// remember keeps a manifest's ecosystem by its ETag. The cache is emptied
// when it holds maxMarks entries, so a long-running service stays bounded.
func (h *Handlers) remember(etag string, eco archive.Ecosystem) {
	h.marksMu.Lock()
	defer h.marksMu.Unlock()
	if h.marks == nil || len(h.marks) >= maxMarks {
		h.marks = make(map[string]archive.Ecosystem)
	}
	h.marks[etag] = eco
}

// addLatestImports gives each archive the id and outcome of its user's newest
// import of the objects now in MinIO: the same archive key with the same
// archive, manifest and signature ETags. Folders reuse their names from one
// export to the next, so an import of an earlier upload must not stand for
// this one. A store that cannot
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
	type objects struct{ archive, manifest, signature, key string }
	latest := map[objects]LatestImport{}
	for i := len(imps) - 1; i >= 0; i-- { // oldest first, so the newest wins
		imp := imps[i]
		at := objects{imp.Archive.ETag, imp.Manifest.ETag, sigOf(imp).ETag, imp.Archive.Key}
		latest[at] = LatestImport{Id: imp.ID, Outcome: imp.Outcome()}
	}
	for i := range archives {
		key := archives[i].Key
		at := objects{etags[key], etags[path.Dir(key)+"/"+manifestName], etags[path.Dir(key)+"/"+signatureName], key}
		if li, ok := latest[at]; ok {
			archives[i].LatestImport = &li
		}
	}
}
