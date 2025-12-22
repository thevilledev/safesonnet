package safesonnet

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/google/go-jsonnet"
)

var (
	// ErrJPathOutsideRoot is returned when a JPath is outside the root directory.
	ErrJPathOutsideRoot = errors.New("jpath is outside root directory")
	// ErrEmptyRootDir is returned when the root directory is empty.
	ErrEmptyRootDir = errors.New("root directory must not be empty")
	// ErrOpenRootDir is returned when the root directory cannot be opened.
	ErrOpenRootDir = errors.New("failed to open root directory")
	// ErrAbsPath is returned when the absolute path cannot be obtained.
	ErrAbsPath = errors.New("failed to get absolute path of root")
	// ErrReadFile is returned when a file cannot be read.
	ErrReadFile = errors.New("failed to read file")
	// ErrFileNotFound is returned when a file is not found in any library path.
	ErrFileNotFound = errors.New("file not found in any library path")
	// ErrForbiddenAbsolutePath is returned when an import path is absolute and outside the root directory.
	ErrForbiddenAbsolutePath = errors.New("forbidden absolute import path")
	// ErrForbiddenRelativePathTraversal is returned when a relative import path attempts to traverse outside the root.
	ErrForbiddenRelativePathTraversal = errors.New("forbidden relative import path traversal")
	// ErrInvalidNullByte is returned when a path contains a null byte, which is invalid.
	ErrInvalidNullByte = errors.New("path contains an invalid null byte")
	// ErrCacheInternalType is returned when the cache contains an unexpected value type.
	ErrCacheInternalType = errors.New("internal cache error: unexpected type")
	// ErrForbiddenPathTraversal is returned for generic path traversal attempts.
	ErrForbiddenPathTraversal = errors.New("forbidden path traversal")
)

// SafeImporter implements jsonnet.Importer that restricts imports to a root directory.
type SafeImporter struct {
	JPaths      []string
	root        *os.Root
	rootAbsPath string
	fsCache     sync.Map
	logger      *log.Logger
}

type cacheEntry struct {
	contents jsonnet.Contents
	foundAt  string
	err      error
}

// Option configures SafeImporter.
type Option func(*SafeImporter)

// WithLogger sets the logger.
func WithLogger(l *log.Logger) Option {
	return func(s *SafeImporter) {
		if l != nil {
			s.logger = l
		}
	}
}

// NewSafeImporter creates a new importer restricted to rootDir.
func NewSafeImporter(rootDir string, jpaths []string, opts ...Option) (*SafeImporter, error) {
	if rootDir == "" {
		return nil, ErrEmptyRootDir
	}

	rootAbs, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAbsPath, err)
	}

	// Use os.OpenRoot for secure directory access
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrOpenRootDir, err)
	}

	cleanJPaths, err := processJPaths(jpaths, rootAbs, root)
	if err != nil {
		root.Close()

		return nil, err
	}

	si := &SafeImporter{
		JPaths:      cleanJPaths,
		root:        root,
		rootAbsPath: rootAbs,
		logger:      log.New(io.Discard, "", 0),
	}
	for _, o := range opts {
		o(si)
	}

	return si, nil
}

func processJPaths(jpaths []string, rootAbs string, root *os.Root) ([]string, error) {
	cleanJPaths := make([]string, 0, len(jpaths)+1)
	effectiveJPaths := jpaths
	if len(jpaths) == 0 {
		effectiveJPaths = []string{"."}
	}

	for _, jp := range effectiveJPaths {
		if jp == "" {
			continue
		}
		if strings.Contains(jp, "\x00") {
			return nil, fmt.Errorf("%w: jpath %q", ErrInvalidNullByte, jp)
		}

		rel, err := resolveJPath(jp, rootAbs, root)
		if err != nil {
			return nil, err
		}

		cleanJPaths = append(cleanJPaths, rel)
	}

	if len(cleanJPaths) == 0 {
		return []string{"."}, nil
	}

	return cleanJPaths, nil
}

func resolveJPath(jp, rootAbs string, root *os.Root) (string, error) {
	absJP := jp
	if !filepath.IsAbs(jp) {
		absJP = filepath.Join(rootAbs, jp)
	}
	absJP = filepath.Clean(absJP)

	rel, err := filepath.Rel(rootAbs, absJP)
	if err != nil || strings.HasPrefix(rel, "..") || (strings.HasPrefix(rel, "/") && rel != ".") {
		return "", fmt.Errorf(
			"%w: jpath %q (interpreted as %q) is outside root directory %q (resolved to %q)",
			ErrJPathOutsideRoot, jp, absJP, root.Name(), rootAbs)
	}

	return rel, nil
}

func (s *SafeImporter) Import(importedFrom, importedPath string) (jsonnet.Contents, string, error) {
	s.logger.Printf("Import: from=%q path=%q", importedFrom, importedPath)

	if strings.Contains(importedPath, "\x00") {
		return jsonnet.Contents{}, "", ErrInvalidNullByte
	}
	if strings.Contains(importedFrom, "\x00") {
		return jsonnet.Contents{}, "", fmt.Errorf("%w: importedFrom %q", ErrInvalidNullByte, importedFrom)
	}

	// 1. Try primary candidate (direct import)
	contents, foundAt, found, err := s.tryPrimaryImport(importedFrom, importedPath)
	if err != nil {
		return jsonnet.Contents{}, "", err
	}
	if found {
		return contents, foundAt, nil
	}

	// 2. Try JPaths
	return s.searchJPaths(importedFrom, importedPath)
}

func (s *SafeImporter) tryPrimaryImport(importedFrom, importedPath string) (jsonnet.Contents, string, bool, error) {
	primaryCandidate, isAbsImport, err := s.resolveImportPath(importedFrom, importedPath)
	if err != nil {
		return jsonnet.Contents{}, "", false, err
	}

	rel, err := filepath.Rel(s.rootAbsPath, primaryCandidate)
	isOutside := err != nil || strings.HasPrefix(rel, "..") || (strings.HasPrefix(rel, "/") && rel != ".")

	if isOutside {
		if isAbsImport {
			return jsonnet.Contents{}, "", false, fmt.Errorf(
				"%w: path %q (resolved to %q) is outside root directory %q",
				ErrForbiddenAbsolutePath, importedPath, primaryCandidate, s.rootAbsPath)
		}
		if importedFrom != "" {
			return jsonnet.Contents{}, "", false, fmt.Errorf(
				"%w: path %q (in search dir %q, resolved to %q) would be outside root directory %q",
				ErrForbiddenRelativePathTraversal,
				importedPath,
				filepath.Dir(importedFrom),
				primaryCandidate,
				s.rootAbsPath,
			)
		}
		// Initial relative import outside root -> Fallback to JPaths
		return jsonnet.Contents{}, "", false, nil
	}

	// Inside root.
	found, contents, foundAt, err := s.tryAbsPath(primaryCandidate, rel)
	if err != nil {
		return jsonnet.Contents{}, "", false, err
	}

	return contents, foundAt, found, nil
}

func (s *SafeImporter) resolveImportPath(importedFrom, importedPath string) (string, bool, error) {
	isAbsImport := filepath.IsAbs(importedPath)
	if isAbsImport {
		return filepath.Clean(importedPath), true, nil
	}

	if importedFrom != "" {
		dir := filepath.Dir(importedFrom)
		if !filepath.IsAbs(dir) {
			absDir, err := filepath.Abs(dir)
			if err != nil {
				return "", false, err
			}
			dir = absDir
		}

		return filepath.Clean(filepath.Join(dir, importedPath)), false, nil
	}

	// Initial import
	abs, err := filepath.Abs(importedPath)
	if err != nil {
		return "", false, fmt.Errorf("error resolving initial path %q to absolute: %w", importedPath, err)
	}

	return filepath.Clean(abs), false, nil
}

func (s *SafeImporter) searchJPaths(importedFrom, importedPath string) (jsonnet.Contents, string, error) {
	searchPaths := s.JPaths
	if importedFrom == "" {
		searchPaths = s.ensureDotInSearchPaths(searchPaths)
	}

	for _, jp := range searchPaths {
		candidate := filepath.Join(s.rootAbsPath, jp, importedPath)
		candidate = filepath.Clean(candidate)

		rel, err := filepath.Rel(s.rootAbsPath, candidate)
		if err != nil || strings.HasPrefix(rel, "..") || (strings.HasPrefix(rel, "/") && rel != ".") {
			continue
		}

		found, contents, foundAt, err := s.tryAbsPath(candidate, rel)
		if err != nil {
			return jsonnet.Contents{}, "", err
		}
		if found {
			return contents, foundAt, nil
		}
	}

	return jsonnet.Contents{}, "", ErrFileNotFound
}

func (s *SafeImporter) ensureDotInSearchPaths(paths []string) []string {
	hasDot := slices.Contains(paths, ".")
	if !hasDot {
		return append([]string{"."}, paths...)
	}

	return paths
}

func (s *SafeImporter) tryAbsPath(absPath, relPath string) (bool, jsonnet.Contents, string, error) {
	if val, ok := s.fsCache.Load(absPath); ok {
		entry, ok := val.(*cacheEntry)
		if !ok {
			return false, jsonnet.Contents{}, "", ErrCacheInternalType
		}
		if entry.err != nil {
			if os.IsNotExist(entry.err) {
				return false, jsonnet.Contents{}, "", nil
			}

			return false, jsonnet.Contents{}, "", entry.err
		}

		return true, entry.contents, entry.foundAt, nil
	}

	f, err := s.root.Open(relPath)
	if err != nil {
		if os.IsNotExist(err) {
			s.fsCache.Store(absPath, &cacheEntry{err: err})

			return false, jsonnet.Contents{}, "", nil
		}

		return false, jsonnet.Contents{}, "", fmt.Errorf("%w: %q: %w", ErrReadFile, relPath, err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return false, jsonnet.Contents{}, "", fmt.Errorf("%w: %q: %w", ErrReadFile, relPath, err)
	}

	contents := jsonnet.MakeContents(string(data))
	s.fsCache.Store(absPath, &cacheEntry{
		contents: contents,
		foundAt:  absPath,
	})

	return true, contents, absPath, nil
}

func (s *SafeImporter) Close() error {
	if s.root != nil {
		return s.root.Close()
	}

	return nil
}

func (s *SafeImporter) getRelativeDir(importedFrom string) (string, error) {
	if strings.Contains(importedFrom, "\x00") {
		return "", fmt.Errorf("%w: importedFrom %q", ErrInvalidNullByte, importedFrom)
	}
	if !filepath.IsAbs(importedFrom) {
		return filepath.Dir(importedFrom), nil
	}
	rel, err := filepath.Rel(s.rootAbsPath, filepath.Dir(importedFrom))
	if err != nil {
		return "", err
	}

	return rel, nil
}
