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

	"witness/internal/canonjson"
	"witness/internal/diag"
	"witness/internal/digest"
)

const (
	SchemaVersion = "witness-source-snapshot-v1"
	Format        = "content-addressed-manifest-v1"

	CodeMissingSource       = "freeze_missing_source"
	CodeMissingOutput       = "freeze_missing_output"
	CodeOutputInsideSource  = "freeze_output_inside_source"
	CodeSourceNotGit        = "freeze_source_not_git"
	CodeSourceUnborn        = "freeze_source_unborn"
	CodeSourceDirty         = "freeze_source_dirty"
	CodeInvalidGitOutput    = "freeze_invalid_git_output"
	CodeUnsupportedFileType = "freeze_unsupported_file_type"
	CodeUnsafePath          = "freeze_unsafe_path"
	CodeUnsafeOutputPath    = "freeze_unsafe_output_path"
	CodeBlobDigestMismatch  = "freeze_blob_digest_mismatch"
)

type Options struct {
	SourceDir   string
	OutputDir   string
	AllowNonGit bool
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
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
	Blob   string `json:"blob"`
}

type sourceFile struct {
	path string
	mode string
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

	source := SourceIdentity{Path: sourceAbs}
	files, gitSource, err := collectGitFiles(ctx, sourceAbs)
	if err != nil {
		if !options.AllowNonGit || !isNonGitError(err) {
			return zero, err
		}
		files, err = collectFilesystemFiles(sourceAbs)
		if err != nil {
			return zero, err
		}
		source.GitTrackedOnly = false
	} else {
		source = gitSource
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
			Size:   size,
			Digest: sum,
			Blob:   filepath.ToSlash(filepath.Join("blobs", "sha256", blobName)),
		})
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

	source := SourceIdentity{Path: sourceAbs}
	files, gitSource, err := collectGitFiles(ctx, sourceAbs)
	if err != nil {
		if !options.AllowNonGit || !isNonGitError(err) {
			return zero, err
		}
		files, err = collectFilesystemFiles(sourceAbs)
		if err != nil {
			return zero, err
		}
		source.GitTrackedOnly = false
	} else {
		source = gitSource
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
			Size:   size,
			Digest: sum,
			Blob:   filepath.ToSlash(filepath.Join("blobs", "sha256", blobName)),
		})
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

func collectGitFiles(ctx context.Context, sourceAbs string) ([]sourceFile, SourceIdentity, error) {
	root, err := gitOutput(ctx, sourceAbs, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, SourceIdentity{}, diag.Wrap(err, CodeSourceNotGit, "source directory must be a Git work tree unless non-Git freezing is explicitly enabled.")
	}
	root = strings.TrimSpace(root)
	if resolvedRoot, err := canonicalPath(root); err == nil {
		root = resolvedRoot
	}
	head, err := gitOutput(ctx, sourceAbs, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return nil, SourceIdentity{}, diag.Wrap(err, CodeSourceUnborn, "source Git work tree must have a committed HEAD.")
	}
	status, err := gitOutput(ctx, sourceAbs, "status", "--porcelain=v1", "-z", "--untracked-files=normal")
	if err != nil {
		return nil, SourceIdentity{}, err
	}
	if status != "" {
		return nil, SourceIdentity{}, diag.New(
			CodeSourceDirty,
			"source Git work tree must be clean before freezing.",
			diag.WithDetail("status_porcelain_z", status),
		)
	}
	stage, err := gitOutput(ctx, sourceAbs, "ls-files", "--stage", "-z")
	if err != nil {
		return nil, SourceIdentity{}, err
	}
	files, err := parseGitStage(stage)
	if err != nil {
		return nil, SourceIdentity{}, err
	}
	return files, SourceIdentity{
		Path:           sourceAbs,
		GitRoot:        root,
		GitHead:        strings.TrimSpace(head),
		GitTrackedOnly: true,
	}, nil
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
