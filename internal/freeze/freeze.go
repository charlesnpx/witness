package freeze

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charlesnpx/witness/internal/canonjson"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/strictjson"
)

const (
	SchemaVersion = "witness-source-snapshot-v1"
	Format        = "content-addressed-manifest-v1"

	CodeMissingSource              = "freeze_missing_source"
	CodeMissingOutput              = "freeze_missing_output"
	CodeOutputInsideSource         = "freeze_output_inside_source"
	CodeSourceNotGit               = "freeze_source_not_git"
	CodeSourceUnborn               = "freeze_source_unborn"
	CodeSourceDirty                = "freeze_source_dirty"
	CodeSourceChangedDuringCapture = "freeze_source_changed_during_capture"
	CodeInvalidGitOutput           = "freeze_invalid_git_output"
	CodeUnsupportedFileType        = "freeze_unsupported_file_type"
	CodeUnsafePath                 = "freeze_unsafe_path"
	CodeUnsafeOutputPath           = "freeze_unsafe_output_path"
	CodeBlobDigestMismatch         = "freeze_blob_digest_mismatch"
	CodeInvalidManifest            = "freeze_invalid_manifest"
)

type Options struct {
	SourceDir        string
	OutputDir        string
	AllowNonGit      bool
	AllowDirtySource bool

	afterDirtySourceCapture func()
}

type Result struct {
	Manifest       Manifest
	ManifestPath   string
	ManifestDigest string
}

type Manifest struct {
	SchemaVersion string            `json:"schema_version"`
	DigestProfile string            `json:"digest_profile"`
	Source        SourceIdentity    `json:"source"`
	Workspace     WorkspaceIdentity `json:"workspace"`
	Files         []FileEntry       `json:"files"`
}

type SourceIdentity struct {
	Path           string `json:"path"`
	GitRoot        string `json:"git_root,omitempty"`
	GitHead        string `json:"git_head,omitempty"`
	GitTrackedOnly bool   `json:"git_tracked_only"`
	GitDirty       bool   `json:"git_dirty,omitempty"`
	GitDirtyStatus string `json:"git_dirty_status,omitempty"`
	ManifestDigest string `json:"manifest_digest,omitempty"`
}

type WorkspaceIdentity struct {
	Path           string `json:"path"`
	Format         string `json:"format"`
	BlobDirectory  string `json:"blob_directory"`
	ManifestPath   string `json:"manifest_path"`
	ManifestDigest string `json:"manifest_digest,omitempty"`
}

type FileEntry struct {
	Path   string           `json:"path"`
	Mode   string           `json:"mode"`
	Size   strictjson.Int64 `json:"size"`
	Digest string           `json:"digest"`
	Blob   string           `json:"blob"`
}

type sourceFile struct {
	path string
	mode string
}

type dirtyGitInventory struct {
	files       []sourceFile
	trackedOnly bool
	status      string
}

// DeriveManifest re-inventories the source and derives the manifest Create would
// write, without creating directories or writing blobs.
func DeriveManifest(ctx context.Context, options Options) (Result, error) {
	var zero Result
	if options.SourceDir == "" {
		return zero, diag.New(CodeMissingSource, "source directory is required.")
	}
	if options.OutputDir == "" {
		return zero, diag.New(CodeMissingOutput, "output directory is required.")
	}
	sourceAbs, err := canonicalPath(options.SourceDir)
	if err != nil {
		return zero, err
	}
	outputAbs, err := canonicalPath(options.OutputDir)
	if err != nil {
		return zero, err
	}
	containmentRoot := sourceAbs
	if gitRoot, err := gitRepositoryRoot(ctx, sourceAbs); err == nil {
		containmentRoot = gitRoot
	}
	if err := ensureOutputOutsideSource(containmentRoot, outputAbs); err != nil {
		return zero, err
	}

	files, source, dirtyInventory, err := collectSourceFiles(ctx, sourceAbs, options)
	if err != nil {
		return zero, err
	}

	entries := make([]FileEntry, 0, len(files))
	for _, item := range files {
		data, size, err := readSnapshotBytes(sourceAbs, item)
		if err != nil {
			return zero, err
		}
		sum := digest.RawBytes(data)
		blobName := strings.TrimPrefix(sum, digest.Prefix)
		entries = append(entries, FileEntry{
			Path:   item.path,
			Mode:   item.mode,
			Size:   strictjson.Int64(size),
			Digest: sum,
			Blob:   filepath.ToSlash(filepath.Join("blobs", "sha256", blobName)),
		})
	}
	if err := verifyDirtyGitCapture(ctx, sourceAbs, dirtyInventory, entries, options.afterDirtySourceCapture); err != nil {
		return zero, err
	}

	manifestPath := filepath.Join(outputAbs, "manifest.json")
	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		DigestProfile: digest.Profile,
		Source:        source,
		Workspace: WorkspaceIdentity{
			Path:          outputAbs,
			Format:        Format,
			BlobDirectory: filepath.Join(outputAbs, "blobs"),
			ManifestPath:  manifestPath,
		},
		Files: entries,
	}
	manifestDigest, err := unsignedManifestDigest(manifest)
	if err != nil {
		return zero, err
	}
	manifest.Source.ManifestDigest = manifestDigest
	manifest.Workspace.ManifestDigest = manifestDigest
	return Result{Manifest: manifest, ManifestPath: manifestPath, ManifestDigest: manifestDigest}, nil
}

func Create(ctx context.Context, options Options) (Result, error) {
	var zero Result
	if options.SourceDir == "" {
		return zero, diag.New(CodeMissingSource, "source directory is required.")
	}
	if options.OutputDir == "" {
		return zero, diag.New(CodeMissingOutput, "output directory is required.")
	}
	sourceAbs, err := canonicalPath(options.SourceDir)
	if err != nil {
		return zero, err
	}
	outputAbs, err := canonicalPath(options.OutputDir)
	if err != nil {
		return zero, err
	}
	containmentRoot := sourceAbs
	if gitRoot, err := gitRepositoryRoot(ctx, sourceAbs); err == nil {
		containmentRoot = gitRoot
	}
	if err := ensureOutputOutsideSource(containmentRoot, outputAbs); err != nil {
		return zero, err
	}

	files, source, dirtyInventory, err := collectSourceFiles(ctx, sourceAbs, options)
	if err != nil {
		return zero, err
	}

	blobRoot := filepath.Join(outputAbs, "blobs", "sha256")
	if err := mkdirAllSnapshotDir(blobRoot, outputAbs); err != nil {
		return zero, err
	}

	entries := make([]FileEntry, 0, len(files))
	for _, item := range files {
		data, size, err := readSnapshotBytes(sourceAbs, item)
		if err != nil {
			return zero, err
		}
		sum := digest.RawBytes(data)
		blobName := strings.TrimPrefix(sum, digest.Prefix)
		blobPath := filepath.Join(blobRoot, blobName)
		if err := writeBlob(blobPath, data, sum); err != nil {
			return zero, err
		}
		entries = append(entries, FileEntry{
			Path:   item.path,
			Mode:   item.mode,
			Size:   strictjson.Int64(size),
			Digest: sum,
			Blob:   filepath.ToSlash(filepath.Join("blobs", "sha256", blobName)),
		})
	}
	if err := verifyDirtyGitCapture(ctx, sourceAbs, dirtyInventory, entries, options.afterDirtySourceCapture); err != nil {
		return zero, err
	}

	manifestPath := filepath.Join(outputAbs, "manifest.json")
	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		DigestProfile: digest.Profile,
		Source:        source,
		Workspace: WorkspaceIdentity{
			Path:          outputAbs,
			Format:        Format,
			BlobDirectory: filepath.Join(outputAbs, "blobs"),
			ManifestPath:  manifestPath,
		},
		Files: entries,
	}
	manifestDigest, err := unsignedManifestDigest(manifest)
	if err != nil {
		return zero, err
	}
	manifest.Source.ManifestDigest = manifestDigest
	manifest.Workspace.ManifestDigest = manifestDigest
	if err := rejectExistingSymlink(manifestPath); err != nil {
		return zero, err
	}
	if err := writeCanonicalFile(manifestPath, manifest); err != nil {
		return zero, err
	}
	return Result{Manifest: manifest, ManifestPath: manifestPath, ManifestDigest: manifestDigest}, nil
}

func ensureOutputOutsideSource(sourceAbs string, outputAbs string) error {
	if outputAbs == sourceAbs {
		return diag.New(CodeOutputInsideSource, "snapshot output directory must be outside the reviewed source tree.")
	}
	rel, err := filepath.Rel(sourceAbs, outputAbs)
	if err != nil {
		return err
	}
	if rel == "." || rel == "" || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." && !filepath.IsAbs(rel)) {
		return diag.New(
			CodeOutputInsideSource,
			"snapshot output directory must be outside the reviewed source tree.",
			diag.WithDetail("source_dir", sourceAbs),
			diag.WithDetail("output_dir", outputAbs),
		)
	}
	return nil
}

func canonicalPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		return resolved, nil
	}
	var missing []string
	current := absolute
	for {
		parent := filepath.Dir(current)
		if parent == current {
			return absolute, nil
		}
		missing = append(missing, filepath.Base(current))
		current = parent
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
	}
}

func gitRepositoryRoot(ctx context.Context, sourceAbs string) (string, error) {
	root, err := gitOutput(ctx, sourceAbs, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	return canonicalPath(strings.TrimSpace(root))
}

func collectSourceFiles(ctx context.Context, sourceAbs string, options Options) ([]sourceFile, SourceIdentity, *dirtyGitInventory, error) {
	source := SourceIdentity{Path: sourceAbs}
	files, gitSource, dirtyInventory, err := collectGitFiles(ctx, sourceAbs, options.AllowDirtySource)
	if err != nil {
		if !options.AllowNonGit || !isNonGitError(err) {
			return nil, SourceIdentity{}, nil, err
		}
		files, err = collectFilesystemFiles(sourceAbs)
		if err != nil {
			return nil, SourceIdentity{}, nil, err
		}
		source.GitTrackedOnly = false
		return files, source, nil, nil
	}
	return files, gitSource, dirtyInventory, nil
}

func collectGitFiles(ctx context.Context, sourceAbs string, allowDirtySource bool) ([]sourceFile, SourceIdentity, *dirtyGitInventory, error) {
	root, err := gitOutput(ctx, sourceAbs, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, SourceIdentity{}, nil, diag.Wrap(err, CodeSourceNotGit, "source directory must be a Git work tree unless non-Git freezing is explicitly enabled.")
	}
	root = strings.TrimSpace(root)
	if resolvedRoot, err := canonicalPath(root); err == nil {
		root = resolvedRoot
	}
	head, err := gitOutput(ctx, sourceAbs, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return nil, SourceIdentity{}, nil, diag.Wrap(err, CodeSourceUnborn, "source Git work tree must have a committed HEAD.")
	}
	status, err := gitOutput(ctx, sourceAbs, "status", "--porcelain=v1", "-z", "--untracked-files=normal")
	if err != nil {
		return nil, SourceIdentity{}, nil, err
	}
	if status != "" {
		if allowDirtySource {
			dirtyInventory, err := collectDirtyGitInventory(ctx, sourceAbs)
			if err != nil {
				return nil, SourceIdentity{}, nil, err
			}
			return dirtyInventory.files, SourceIdentity{
				Path:           sourceAbs,
				GitRoot:        root,
				GitHead:        strings.TrimSpace(head),
				GitTrackedOnly: dirtyInventory.trackedOnly,
				GitDirty:       true,
				GitDirtyStatus: dirtyInventory.status,
			}, dirtyInventory, nil
		}
		return nil, SourceIdentity{}, nil, diag.New(
			CodeSourceDirty,
			"source Git work tree must be clean before freezing.",
			diag.WithDetail("status_porcelain_z", status),
		)
	}
	stage, err := gitOutput(ctx, sourceAbs, "ls-files", "--stage", "-z")
	if err != nil {
		return nil, SourceIdentity{}, nil, err
	}
	files, err := parseGitStage(stage)
	if err != nil {
		return nil, SourceIdentity{}, nil, err
	}
	return files, SourceIdentity{
		Path:           sourceAbs,
		GitRoot:        root,
		GitHead:        strings.TrimSpace(head),
		GitTrackedOnly: true,
	}, nil, nil
}

func collectDirtyGitInventory(ctx context.Context, sourceAbs string) (*dirtyGitInventory, error) {
	files, trackedOnly, err := collectDirtyGitFiles(ctx, sourceAbs)
	if err != nil {
		return nil, err
	}
	summary, err := gitOutput(ctx, sourceAbs, "status", "--porcelain=v1", "--untracked-files=normal")
	if err != nil {
		return nil, err
	}
	return &dirtyGitInventory{
		files:       files,
		trackedOnly: trackedOnly,
		status:      strings.TrimSpace(summary),
	}, nil
}

func verifyDirtyGitCapture(ctx context.Context, sourceAbs string, before *dirtyGitInventory, entries []FileEntry, afterCapture func()) error {
	if before == nil {
		return nil
	}
	if afterCapture != nil {
		afterCapture()
	}
	after, err := collectDirtyGitInventory(ctx, sourceAbs)
	if err != nil {
		return err
	}
	contentUnchanged := capturedFileDigestsMatch(sourceAbs, before.files, entries)
	if dirtyGitInventoriesEqual(*before, *after) && contentUnchanged {
		return nil
	}
	return diag.New(
		CodeSourceChangedDuringCapture,
		"source worktree mutated during freeze; quiesce the worktree and retry.",
		diag.WithDetail("before_status", before.status),
		diag.WithDetail("after_status", after.status),
	)
}

// capturedFileDigestsMatch re-reads every file captured from the working tree.
// A false result includes a path which disappeared or ceased to match its
// captured file type while the snapshot was being made.
func capturedFileDigestsMatch(sourceAbs string, capturedFiles []sourceFile, entries []FileEntry) bool {
	capturedDigests := make(map[string]string, len(entries))
	for _, entry := range entries {
		capturedDigests[entry.Path] = entry.Digest
	}
	for _, item := range capturedFiles {
		capturedDigest, found := capturedDigests[item.path]
		if !found {
			return false
		}
		data, _, err := readSnapshotBytes(sourceAbs, item)
		if err != nil || digest.RawBytes(data) != capturedDigest {
			return false
		}
	}
	return true
}

func dirtyGitInventoriesEqual(left dirtyGitInventory, right dirtyGitInventory) bool {
	if left.trackedOnly != right.trackedOnly || left.status != right.status || len(left.files) != len(right.files) {
		return false
	}
	for index := range left.files {
		if left.files[index] != right.files[index] {
			return false
		}
	}
	return true
}

// collectDirtyGitFiles inventories the work tree as it is now: tracked files
// use their on-disk mode and bytes, deleted tracked files are absent, and
// non-ignored untracked files are included.
func collectDirtyGitFiles(ctx context.Context, sourceAbs string) ([]sourceFile, bool, error) {
	stage, err := gitOutput(ctx, sourceAbs, "ls-files", "--stage", "-z")
	if err != nil {
		return nil, false, err
	}
	tracked, err := parseGitStage(stage)
	if err != nil {
		return nil, false, err
	}
	files := make(map[string]sourceFile, len(tracked))
	for _, item := range tracked {
		file, present, err := sourceFileFromWorkingTree(sourceAbs, item.path)
		if err != nil {
			return nil, false, err
		}
		if present {
			files[file.path] = file
		}
	}

	untrackedOutput, err := gitOutput(ctx, sourceAbs, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, false, err
	}
	untracked, err := parseGitPaths(untrackedOutput)
	if err != nil {
		return nil, false, err
	}
	for _, path := range untracked {
		file, present, err := sourceFileFromWorkingTree(sourceAbs, path)
		if err != nil {
			return nil, false, err
		}
		if present {
			files[file.path] = file
		}
	}

	items := make([]sourceFile, 0, len(files))
	for _, item := range files {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].path < items[j].path })
	return items, len(untracked) == 0, nil
}

func parseGitPaths(output string) ([]string, error) {
	if output == "" {
		return nil, nil
	}
	paths := make([]string, 0, strings.Count(output, "\x00"))
	for _, path := range strings.Split(output, "\x00") {
		if path == "" {
			continue
		}
		if err := validateRelativePath(path); err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}

func sourceFileFromWorkingTree(sourceAbs string, relativePath string) (sourceFile, bool, error) {
	path := filepath.Join(sourceAbs, filepath.FromSlash(relativePath))
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return sourceFile{}, false, nil
	}
	if err != nil {
		return sourceFile{}, false, err
	}
	mode, err := fileModeString(info.Mode())
	if err != nil {
		return sourceFile{}, false, err
	}
	return sourceFile{path: relativePath, mode: mode}, true, nil
}

func collectFilesystemFiles(sourceAbs string) ([]sourceFile, error) {
	var files []sourceFile
	err := filepath.WalkDir(sourceAbs, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(sourceAbs, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if err := validateRelativePath(rel); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		mode, err := fileModeString(info.Mode())
		if err != nil {
			return err
		}
		files = append(files, sourceFile{path: rel, mode: mode})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	return files, nil
}

func parseGitStage(stage string) ([]sourceFile, error) {
	if stage == "" {
		return nil, nil
	}
	records := strings.Split(stage, "\x00")
	files := make([]sourceFile, 0, len(records))
	for _, record := range records {
		if record == "" {
			continue
		}
		tab := strings.IndexByte(record, '\t')
		if tab < 0 {
			return nil, diag.New(CodeInvalidGitOutput, "git ls-files output did not contain a path separator.")
		}
		meta := strings.Fields(record[:tab])
		if len(meta) < 3 {
			return nil, diag.New(CodeInvalidGitOutput, "git ls-files output did not contain mode, object, and stage fields.")
		}
		mode := meta[0]
		switch mode {
		case "100644", "100755", "120000":
		default:
			return nil, diag.New(CodeUnsupportedFileType, "source contains a Git file mode Witness cannot freeze.", diag.WithDetail("mode", mode))
		}
		path := record[tab+1:]
		if err := validateRelativePath(path); err != nil {
			return nil, err
		}
		files = append(files, sourceFile{path: path, mode: mode})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	return files, nil
}

func validateRelativePath(path string) error {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\x00") {
		return diag.New(CodeUnsafePath, "snapshot path must be a non-empty relative path.", diag.WithDetail("path", path))
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return diag.New(CodeUnsafePath, "snapshot path must not contain empty, current, or parent segments.", diag.WithDetail("path", path))
		}
	}
	return nil
}

func readSnapshotBytes(sourceAbs string, item sourceFile) ([]byte, int64, error) {
	path := filepath.Join(sourceAbs, filepath.FromSlash(item.path))
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	switch item.mode {
	case "120000":
		if info.Mode()&os.ModeSymlink == 0 {
			return nil, 0, diag.New(CodeUnsupportedFileType, "Git symlink entry is not a filesystem symlink.", diag.WithDetail("path", item.path))
		}
		target, err := os.Readlink(path)
		if err != nil {
			return nil, 0, err
		}
		data := []byte(target)
		return data, int64(len(data)), nil
	case "100644", "100755":
		if !info.Mode().IsRegular() {
			return nil, 0, diag.New(CodeUnsupportedFileType, "Git file entry is not a regular filesystem file.", diag.WithDetail("path", item.path))
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, 0, err
		}
		return data, int64(len(data)), nil
	default:
		return nil, 0, diag.New(CodeUnsupportedFileType, "unsupported snapshot file mode.", diag.WithDetail("mode", item.mode))
	}
}

func fileModeString(mode fs.FileMode) (string, error) {
	if mode&os.ModeSymlink != 0 {
		return "120000", nil
	}
	if !mode.IsRegular() {
		return "", diag.New(CodeUnsupportedFileType, "source contains a filesystem entry Witness cannot freeze.")
	}
	if mode&0o111 != 0 {
		return "100755", nil
	}
	return "100644", nil
}

func mkdirAllSnapshotDir(path string, outputAbs string) error {
	for _, dir := range []string{
		filepath.Join(outputAbs, "blobs"),
		filepath.Join(outputAbs, "blobs", "sha256"),
	} {
		if err := rejectExistingSymlink(dir); err != nil {
			return err
		}
	}
	return os.MkdirAll(path, 0o755)
}

func rejectExistingSymlink(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return diag.New(
				CodeUnsafeOutputPath,
				"snapshot output path must not be a pre-existing symlink.",
				diag.WithDetail("path", path),
			)
		}
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func writeBlob(path string, data []byte, expectedDigest string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return diag.New(
				CodeUnsafeOutputPath,
				"snapshot blob path must not be a pre-existing symlink.",
				diag.WithDetail("blob_path", path),
			)
		}
		if !info.Mode().IsRegular() {
			return diag.New(
				CodeUnsafeOutputPath,
				"snapshot blob path must be a regular file when it already exists.",
				diag.WithDetail("blob_path", path),
			)
		}
		existing, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if digest.RawBytes(existing) != expectedDigest {
			return diag.New(CodeBlobDigestMismatch, "existing content-addressed blob does not match its digest name.", diag.WithDetail("blob_path", path))
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return writeBlob(path, data, expectedDigest)
		}
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func unsignedManifestDigest(manifest Manifest) (string, error) {
	projection := map[string]any{
		"schema_version": manifest.SchemaVersion,
		"digest_profile": manifest.DigestProfile,
		"source": map[string]any{
			"path":             manifest.Source.Path,
			"git_root":         manifest.Source.GitRoot,
			"git_head":         manifest.Source.GitHead,
			"git_tracked_only": manifest.Source.GitTrackedOnly,
		},
		"files": manifest.Files,
	}
	encoded, err := canonjson.Marshal(projection)
	if err != nil {
		return "", err
	}
	return digest.RawBytes(encoded), nil
}

func ManifestDigest(manifest Manifest) (string, error) {
	return unsignedManifestDigest(manifest)
}

func ValidateManifest(manifest Manifest) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if manifest.SchemaVersion != SchemaVersion {
		diagnostics = append(diagnostics, manifestDiagnostic("freeze manifest schema_version is unsupported.", "/schema_version", map[string]any{"actual": manifest.SchemaVersion, "expected": SchemaVersion}))
	}
	if manifest.DigestProfile != digest.Profile {
		diagnostics = append(diagnostics, manifestDiagnostic("freeze manifest digest_profile is unsupported.", "/digest_profile", map[string]any{"actual": manifest.DigestProfile, "expected": digest.Profile}))
	}
	seen := map[string]int{}
	for index, file := range manifest.Files {
		path := fmt.Sprintf("/files/%d", index)
		if err := validateRelativePath(file.Path); err != nil {
			diagnostics = append(diagnostics, manifestDiagnostic("freeze manifest file path must be safe and relative.", path+"/path", map[string]any{"path": file.Path}))
		}
		if first, exists := seen[file.Path]; exists {
			diagnostics = append(diagnostics, manifestDiagnostic("freeze manifest file paths must be unique.", path+"/path", map[string]any{"path": file.Path, "duplicate_of": fmt.Sprintf("/files/%d/path", first)}))
		}
		seen[file.Path] = index
		if !validManifestDigest(file.Digest) {
			diagnostics = append(diagnostics, manifestDiagnostic("freeze manifest file digest must be a relay-root-digests-v1 sha256 digest.", path+"/digest", map[string]any{"digest": file.Digest}))
		}
		if file.Size < 0 {
			diagnostics = append(diagnostics, manifestDiagnostic("freeze manifest file size must not be negative.", path+"/size", map[string]any{"size": file.Size}))
		}
	}
	actualDigest, err := unsignedManifestDigest(manifest)
	if err != nil {
		diagnostics = append(diagnostics, manifestDiagnostic("freeze manifest digest could not be computed.", "", map[string]any{"error": err.Error()}))
		return diagnostics
	}
	for _, embedded := range []struct {
		path  string
		value string
	}{
		{path: "/source/manifest_digest", value: manifest.Source.ManifestDigest},
		{path: "/workspace/manifest_digest", value: manifest.Workspace.ManifestDigest},
	} {
		if strings.TrimSpace(embedded.value) == "" {
			continue
		}
		if !validManifestDigest(embedded.value) {
			diagnostics = append(diagnostics, manifestDiagnostic("freeze manifest embedded digest must be a relay-root-digests-v1 sha256 digest.", embedded.path, map[string]any{"digest": embedded.value}))
			continue
		}
		if embedded.value != actualDigest {
			diagnostics = append(diagnostics, manifestDiagnostic("freeze manifest embedded digest does not match its content.", embedded.path, map[string]any{"actual_digest": actualDigest, "expected_digest": embedded.value}))
		}
	}
	return diagnostics
}

func manifestDiagnostic(message string, path string, details map[string]any) diag.Diagnostic {
	return diag.Diagnostic{Code: CodeInvalidManifest, Message: message, Path: path, Details: details}
}

func validManifestDigest(value string) bool {
	if !strings.HasPrefix(value, digest.Prefix) {
		return false
	}
	hex := strings.TrimPrefix(value, digest.Prefix)
	if len(hex) != 64 {
		return false
	}
	for _, char := range hex {
		switch {
		case char >= '0' && char <= '9':
		case char >= 'a' && char <= 'f':
		default:
			return false
		}
	}
	return true
}

func writeCanonicalFile(path string, value any) error {
	encoded, err := canonjson.Marshal(value)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := rejectExistingSymlink(path); err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0o644)
}

func gitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	command.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if stderr.Len() > 0 {
			return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return "", err
	}
	return stdout.String(), nil
}

func isNonGitError(err error) bool {
	var diagnostic *diag.Error
	return errors.As(err, &diagnostic) && diagnostic.Diagnostic.Code == CodeSourceNotGit
}
