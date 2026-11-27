package service

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path"
	"regexp"
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
	// maxCheckReads is how many manifests one list reads that it has not read before: 50.
	maxCheckReads = 50
	// maxCheckBytes is how many bytes of manifests and signatures one list reads: 64 MiB.
	maxCheckBytes = 64 << 20
	// maxMarks is how many folder checks the cache keeps: 4,096.
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
	reasonUnknownKey  = "signed with a key this side does not trust"
	reasonMismatch    = "its signature does not match its manifest"
	reasonSize        = "the archive does not match its manifest"
	reasonManifest    = "its manifest cannot be read"
	reasonSignature   = "its " + signatureName + " cannot be read"
)

var lowerSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

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
	// must pass too. The folder holds no escape, so decoding keeps it in place.
	// An escape that does not decode is a plain name.
	if decoded, err := url.PathUnescape(key); err == nil && decoded != key {
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
	h.checkFolders(lctx, out.Bucket, out.Archives, listed)
	h.addLatestImports(user, out.Archives, listed)
	return ListArchives200JSONResponse(out), nil
}

// checkFolders checks each importable archive's manifest signature with the
// trusted key, then reads its crossing from the manifest the signature
// verified, and refuses the archive when a check fails. One list reads at
// most maxCheckReads manifests it has not read before, and at most
// maxCheckBytes of manifests and signatures, each within its own bound and
// with its listed ETag; an archive past either bound stays not checked until
// a later list. The attempt checks everything again.
func (h *Handlers) checkFolders(ctx context.Context, bucket string, archives []Archive, listed []s3.Object) {
	objects := make(map[string]s3.Object, len(listed))
	for _, o := range listed {
		objects[o.Key] = o
	}
	trusted := len(h.settings.PublicKey) == ed25519.PublicKeySize
	reads, bytes := 0, int64(0)
	for i := range archives {
		a := &archives[i]
		dir := path.Dir(a.Key) + "/"
		m, hasManifest := objects[dir+manifestName]
		s, hasSignature := objects[dir+signatureName]
		a.Files = filesOf(objects, a.Key, dir)
		folder, ok := FolderOf(a.Key)
		state := ArchiveSignatureNotChecked
		if !hasSignature {
			state = ArchiveSignatureUnsigned
		}
		a.Signature = &state
		if !a.Importable || !ok || !hasManifest || !hasSignature || !trusted {
			continue
		}
		id := checkID(bucket, m, s)
		c, known := h.recall(id)
		switch {
		case known:
		case m.Size > archive.MaxManifestSize:
			c = folderCheck{signature: ArchiveSignatureUnreadable, reason: reasonManifest}
			h.remember(id, c)
		case s.Size > archive.MaxSignatureSize:
			c = folderCheck{signature: ArchiveSignatureUnreadable, reason: reasonSignature}
			h.remember(id, c)
		case !validETag(m.ETag) || !validETag(s.ETag) || reads == maxCheckReads || bytes+m.Size+s.Size > maxCheckBytes:
			continue
		default:
			reads, bytes = reads+1, bytes+m.Size+s.Size
			manifest, err := h.readListed(ctx, bucket, m)
			var sig []byte
			if err == nil {
				sig, err = h.readListed(ctx, bucket, s)
			}
			if err != nil {
				// A read that failed may pass on a later list.
				continue
			}
			c = checkFolder(manifest, sig, h.settings.PublicKey, folder)
			h.remember(id, c)
		}
		c.apply(a)
	}
}

// folderCheck is what one read of a folder's manifest and signature proved.
// It holds nothing a manifest says unless its signature verified.
type folderCheck struct {
	eco       archive.Ecosystem
	signature ArchiveSignature
	// signer is the key sha256 the signature file names, on an unknown key only.
	signer string
	// reason says why the archive cannot be imported; empty when the checks pass.
	reason   string
	project  string
	sealedAt string
	packages int
	declared int64
}

// checkFolder verifies manifest against the signature file with the trusted
// key, then reads the verified manifest's ecosystem, crossing and declared
// size. The file's own key sha256 only picks the words of a refusal.
func checkFolder(manifest, sig []byte, trusted ed25519.PublicKey, folder archive.Ecosystem) folderCheck {
	if err := archive.CheckSignature(manifest, sig, trusted); err != nil {
		named, ok := signerOf(sig)
		switch {
		case !ok:
			return folderCheck{signature: ArchiveSignatureUnreadable, reason: reasonSignature}
		case named != archive.PublicKeySHA256(trusted):
			return folderCheck{signature: ArchiveSignatureUnknownKey, signer: named, reason: reasonUnknownKey}
		}
		return folderCheck{signature: ArchiveSignatureMismatch, reason: reasonMismatch}
	}
	c := folderCheck{signature: ArchiveSignatureVerified}
	eco, err := archive.ManifestEcosystem(manifest)
	if err != nil {
		c.reason = reasonManifest
		return c
	}
	c.eco = eco
	var review *archive.Review
	switch eco {
	case archive.Pip:
		var p archive.PipManifest
		if p, err = archive.ParsePipManifest(manifest); err == nil {
			c.sealedAt, c.packages, c.declared, review = p.CreatedAt, len(p.Packages), p.Archive.Size, p.Review
		}
	default:
		var n archive.Manifest
		if n, err = archive.ParseManifest(manifest); err == nil {
			c.sealedAt, c.packages, c.declared, review = n.CreatedAt, len(n.Packages), n.Archive.Size, n.Review
		}
	}
	if review != nil {
		c.project = review.Project
	}
	switch {
	case eco != folder:
		c.reason = "its manifest is " + article(eco) + " " + string(eco) + " archive's: keep the three files under " + folderFor(eco)
	case err != nil:
		c.reason = reasonManifest
	}
	return c
}

// apply puts the check on its archive's row. The size the manifest states
// is compared with the archive listed now, which the check's key does not
// cover.
func (c folderCheck) apply(a *Archive) {
	state := c.signature
	a.Signature = &state
	if c.signer != "" {
		a.SignerKeySha256 = ptr(c.signer)
	}
	if c.signature == ArchiveSignatureVerified && c.sealedAt != "" {
		a.Crossing = &Crossing{SealedAt: c.sealedAt, Packages: c.packages}
		if c.project != "" {
			a.Crossing.Project = ptr(c.project)
		}
		a.DeclaredSize = ptr(c.declared)
	}
	reason := c.reason
	if reason == "" && a.DeclaredSize != nil && *a.DeclaredSize != a.Size {
		reason = reasonSize
	}
	if reason != "" {
		a.Importable, a.Reason = false, &reason
	}
}

// signerOf returns the key sha256 a signature file names, and whether the
// file has a signature's shape: the ed25519 algorithm, a key sha256 of 64
// lowercase hex digits and a base64 signature of 64 bytes.
func signerOf(sig []byte) (string, bool) {
	var doc struct {
		Algorithm       string `json:"algorithm"`
		PublicKeySha256 string `json:"publicKeySha256"`
		Signature       string `json:"signature"`
	}
	if json.Unmarshal(sig, &doc) != nil || doc.Algorithm != "ed25519" || !lowerSHA256.MatchString(doc.PublicKeySha256) {
		return "", false
	}
	if raw, err := base64.StdEncoding.Strict().DecodeString(doc.Signature); err != nil || len(raw) != ed25519.SignatureSize {
		return "", false
	}
	return doc.PublicKeySha256, true
}

// filesOf lists the archive, manifest.json and manifest.json.sig of an
// archive's folder as MinIO listed them, each when present.
func filesOf(objects map[string]s3.Object, archiveKey, dir string) *[]ArchiveFile {
	files := []ArchiveFile{}
	for _, key := range []string{archiveKey, dir + manifestName, dir + signatureName} {
		if o, ok := objects[key]; ok {
			files = append(files, ArchiveFile{Name: cleanText(path.Base(key)), Size: o.Size, Modified: o.LastModified})
		}
	}
	return &files
}

func article(eco archive.Ecosystem) string {
	if eco == archive.NPM {
		return "an"
	}
	return "a"
}

// readListed reads an object with its listed ETag and no more than its
// listed size. A read that ends short is an error: it may pass later.
func (h *Handlers) readListed(ctx context.Context, bucket string, o s3.Object) ([]byte, error) {
	body, _, err := h.objects.Get(ctx, bucket, o.Key, o.ETag)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, o.Size))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != o.Size {
		return nil, errors.New("the object ended before its listed size")
	}
	return data, nil
}

// checkID names a folder's check by its bucket, and the key and ETag of its
// manifest and its signature. Two objects may share an ETag, so one user's
// files never answer for another's, and a replaced file is read again.
func checkID(bucket string, m, s s3.Object) string {
	return strings.Join([]string{bucket, m.Key, m.ETag, s.Key, s.ETag}, "\x00")
}

// recall returns the check remembered under id.
func (h *Handlers) recall(id string) (folderCheck, bool) {
	h.marksMu.Lock()
	defer h.marksMu.Unlock()
	c, ok := h.marks[id]
	return c, ok
}

// remember keeps a check under id. The cache is emptied when it holds
// maxMarks entries, so a long-running service stays bounded.
func (h *Handlers) remember(id string, c folderCheck) {
	h.marksMu.Lock()
	defer h.marksMu.Unlock()
	if h.marks == nil || len(h.marks) >= maxMarks {
		h.marks = make(map[string]folderCheck)
	}
	h.marks[id] = c
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
