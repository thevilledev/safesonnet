package safesonnet

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
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
	cacheMu     sync.RWMutex
	fsCache     map[string]cacheEntry
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

	cleanJPaths, err := processJPaths(jpaths, rootAbs)
	if err != nil {
		root.Close()

		return nil, err
	}

	si := &SafeImporter{
		JPaths:      cleanJPaths,
		root:        root,
		rootAbsPath: rootAbs,
		fsCache:     make(map[string]cacheEntry),
		logger:      log.New(io.Discard, "", 0),
	}
	for _, o := range opts {
		o(si)
	}

	return si, nil
}

func processJPaths(jpaths []string, rootAbs string) ([]string, error) {
	if len(jpaths) == 0 {
		return []string{"."}, nil
	}

	cleanJPaths := make([]string, 0, len(jpaths))
	for _, jp := range jpaths {
		if jp == "" {
			continue
		}
		if strings.Contains(jp, "\x00") {
			return nil, fmt.Errorf("%w: jpath %q", ErrInvalidNullByte, jp)
		}

		rel, err := resolveJPath(jp, rootAbs)
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

func resolveJPath(jp, rootAbs string) (string, error) {
	absJP := jp
	if !filepath.IsAbs(jp) {
		absJP = filepath.Join(rootAbs, jp)
	}
	absJP = filepath.Clean(absJP)

	rel, inside, err := relToRoot(rootAbs, absJP)
	if err != nil || !inside {
		return "", fmt.Errorf(
			"%w: jpath %q (interpreted as %q) is outside root directory %q (resolved to %q)",
			ErrJPathOutsideRoot, jp, absJP, rootAbs, rootAbs)
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

	contents, foundAt, found, err := s.tryPrimaryImport(importedFrom, importedPath)
	if err != nil {
		return jsonnet.Contents{}, "", err
	}
	if found {
		return contents, foundAt, nil
	}

	return s.searchJPaths(importedFrom, importedPath)
}

func (s *SafeImporter) tryPrimaryImport(importedFrom, importedPath string) (jsonnet.Contents, string, bool, error) {
	primaryCandidate, isAbsImport, err := s.resolveImportPath(importedFrom, importedPath)
	if err != nil {
		return jsonnet.Contents{}, "", false, err
	}

	rel, inside, err := relToRoot(s.rootAbsPath, primaryCandidate)
	if err != nil {
		return jsonnet.Contents{}, "", false, err
	}
	if !inside {
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

		return jsonnet.Contents{}, "", false, nil
	}

	return s.loadFile(primaryCandidate, rel)
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
	for _, jp := range s.searchPaths(importedFrom) {
		candidate := filepath.Join(s.rootAbsPath, jp, importedPath)
		candidate = filepath.Clean(candidate)

		rel, inside, err := relToRoot(s.rootAbsPath, candidate)
		if err != nil || !inside {
			continue
		}

		contents, foundAt, found, err := s.loadFile(candidate, rel)
		if err != nil {
			return jsonnet.Contents{}, "", err
		}
		if found {
			return contents, foundAt, nil
		}
	}

	return jsonnet.Contents{}, "", ErrFileNotFound
}

func (s *SafeImporter) searchPaths(importedFrom string) []string {
	if importedFrom != "" || hasDotPath(s.JPaths) {
		return s.JPaths
	}

	paths := make([]string, 0, len(s.JPaths)+1)
	paths = append(paths, ".")

	return append(paths, s.JPaths...)
}

func hasDotPath(paths []string) bool {
	for _, path := range paths {
		if path == "." {
			return true
		}
	}

	return false
}

func (s *SafeImporter) loadFile(absPath, relPath string) (jsonnet.Contents, string, bool, error) {
	if entry, ok := s.cached(absPath); ok {
		return entry.result()
	}

	f, err := s.root.Open(relPath)
	if err != nil {
		if os.IsNotExist(err) {
			s.cache(absPath, cacheEntry{err: err})

			return jsonnet.Contents{}, "", false, nil
		}

		return jsonnet.Contents{}, "", false, fmt.Errorf("%w: %q: %w", ErrReadFile, relPath, err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return jsonnet.Contents{}, "", false, fmt.Errorf("%w: %q: %w", ErrReadFile, relPath, err)
	}

	contents := jsonnet.MakeContents(string(data))
	s.cache(absPath, cacheEntry{
		contents: contents,
		foundAt:  absPath,
	})

	return contents, absPath, true, nil
}

func (s *SafeImporter) cached(absPath string) (cacheEntry, bool) {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()

	entry, ok := s.fsCache[absPath]

	return entry, ok
}

func (s *SafeImporter) cache(absPath string, entry cacheEntry) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	s.fsCache[absPath] = entry
}

func (e cacheEntry) result() (jsonnet.Contents, string, bool, error) {
	if e.err != nil {
		if os.IsNotExist(e.err) {
			return jsonnet.Contents{}, "", false, nil
		}

		return jsonnet.Contents{}, "", false, e.err
	}

	return e.contents, e.foundAt, true, nil
}

func relToRoot(rootAbs, absPath string) (string, bool, error) {
	rel, err := filepath.Rel(rootAbs, filepath.Clean(absPath))
	if err != nil {
		return "", false, err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return rel, false, nil
	}

	return rel, true, nil
}

func (s *SafeImporter) Close() error {
	if s.root != nil {
		return s.root.Close()
	}

	return nil
}
