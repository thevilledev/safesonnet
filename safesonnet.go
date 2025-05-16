package safesonnet

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	// ErrAbsPathJPath is returned when the absolute path of a JPath cannot be obtained.
	ErrAbsPathJPath = errors.New("failed to get absolute path of jpath")
	// ErrRelPath is returned when the relative path cannot be obtained.
	ErrRelPath = errors.New("failed to get relative path of jpath")
	// ErrReadFile is returned when a file cannot be read.
	ErrReadFile = errors.New("failed to read file")
	// ErrOpenFile is returned when a file cannot be opened.
	ErrOpenFile = errors.New("failed to open file")
	// ErrRootAbsPath is returned when the root absolute path cannot be obtained.
	ErrRootAbsPath = errors.New("failed to get root absolute path")
	// ErrRelPathConversion is returned when a relative path cannot be obtained.
	ErrRelPathConversion = errors.New("failed to convert path to be relative to root")
	// ErrFileNotFound is returned when a file is not found in any library path.
	ErrFileNotFound = errors.New("file not found in any library path")
	// ErrCloseRootDir is returned when the root directory cannot be closed.
	ErrCloseRootDir = errors.New("failed to close root directory")
	// ErrCacheInternalType is returned when the cache contains an unexpected value type.
	ErrCacheInternalType = errors.New("internal cache error: unexpected type")
)

// SafeImporter implements jsonnet.Importer interface that restricts imports to a specific directory.
// It prevents path traversal attacks by ensuring all imports are within the specified root directory.
// The importer supports a list of library paths (JPaths) within the root directory,
// similar to the standard jsonnet importer. Caches file reads.
type SafeImporter struct {
	// JPaths is a list of library search paths within the root directory.
	JPaths  []string
	root    *os.Root
	fsCache sync.Map
}

type fsCacheEntry struct {
	contents jsonnet.Contents
	exists   bool
}

// NewSafeImporter creates a new SafeImporter that restricts imports to the given directory.
// It validates that all provided JPaths are within the root directory to maintain
// the security boundary. If no JPaths are provided, the root directory is used as
// the only search path.
//
// rootDir must be a valid directory path or an error will be returned.
// jpaths should be a list of directories inside rootDir to search for imports.
func NewSafeImporter(rootDir string, jpaths []string) (*SafeImporter, error) {
	if rootDir == "" {
		return nil, ErrEmptyRootDir
	}

	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrOpenRootDir, rootDir, err)
	}

	// Convert JPaths to be relative to root if needed
	cleanJPaths := make([]string, 0, len(jpaths))
	rootAbs, err := filepath.Abs(rootDir)
	if err != nil {
		root.Close()

		return nil, fmt.Errorf("%w: %w", ErrAbsPath, err)
	}

	for _, jpath := range jpaths {
		if jpath == "" {
			continue
		}
		// Convert to absolute path
		absPath, err := filepath.Abs(jpath)
		if err != nil {
			root.Close()

			return nil, fmt.Errorf("%w: %q: %w", ErrAbsPathJPath, jpath, err)
		}
		// Ensure path is within root
		if !isSubpath(rootAbs, absPath) {
			root.Close()

			return nil, fmt.Errorf("%w: %q", ErrJPathOutsideRoot, jpath)
		}
		// Convert to root-relative path
		relPath, err := filepath.Rel(rootAbs, absPath)
		if err != nil {
			root.Close()

			return nil, fmt.Errorf("%w: %q: %w", ErrRelPath, jpath, err)
		}
		cleanJPaths = append(cleanJPaths, relPath)
	}

	// If no JPaths provided, use root as the only path
	if len(cleanJPaths) == 0 {
		cleanJPaths = []string{"."}
	}

	return &SafeImporter{
		JPaths: cleanJPaths,
		root:   root,
	}, nil
}

// tryPath attempts to import a file from the root directory.
// It handles caching of file contents and existence checks using sync.Map.
func (i *SafeImporter) tryPath(dir, importedPath string) (bool, jsonnet.Contents, string, error) {
	// Create absolute path for cache key
	var absPath string
	if filepath.IsAbs(importedPath) {
		absPath = importedPath
	} else {
		absPath = filepath.Join(dir, importedPath)
	}

	// Check cache first using sync.Map Load
	if value, isCached := i.fsCache.Load(absPath); isCached {
		entry, ok := value.(*fsCacheEntry) // Assert type
		if !ok {
			// Handle unexpected type in cache - this indicates a programming error or cache corruption.
			// Returning an error is safer than panicking.
			// Wrap the static error ErrCacheInternalType
			return false, jsonnet.Contents{}, "", fmt.Errorf("%w for key %q", ErrCacheInternalType, absPath)
		}
		if !entry.exists {
			return false, jsonnet.Contents{}, "", nil
		}

		return true, entry.contents, absPath, nil
	}

	// Try to open and read the file
	var relPath string
	if filepath.IsAbs(importedPath) {
		// Absolute paths are not allowed
		// Cache the negative result using sync.Map Store
		i.fsCache.Store(absPath, &fsCacheEntry{exists: false})

		return false, jsonnet.Contents{}, "", nil
	}

	// For relative paths, join with the search directory
	relPath = filepath.Join(dir, importedPath)

	// Clean the path to remove any . or .. components
	relPath = filepath.Clean(relPath)

	f, err := i.root.Open(relPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Cache the negative result using sync.Map Store
			i.fsCache.Store(absPath, &fsCacheEntry{exists: false})

			return false, jsonnet.Contents{}, "", nil
		}

		return false, jsonnet.Contents{}, "", fmt.Errorf("%w: %q: %w", ErrOpenFile, relPath, err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return false, jsonnet.Contents{}, "", fmt.Errorf("%w: %q: %w", ErrReadFile, relPath, err)
	}

	// Cache the positive result using sync.Map Store
	contents := jsonnet.MakeContents(string(data))
	i.fsCache.Store(absPath, &fsCacheEntry{
		exists:   true,
		contents: contents,
	})

	return true, contents, absPath, nil
}

// getRelativeDir returns the directory that importedFrom is in, relative to the importer's root.
// This helps resolve relative imports when importing from another file.
func (i *SafeImporter) getRelativeDir(importedFrom string) (string, error) {
	if !filepath.IsAbs(importedFrom) {
		return filepath.Dir(importedFrom), nil
	}

	rootName := i.root.Name()
	rootAbs, err := filepath.Abs(rootName)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrRootAbsPath, err)
	}

	relDir, err := filepath.Rel(rootAbs, filepath.Dir(importedFrom))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrRelPathConversion, err)
	}

	return relDir, nil
}

// tryImport attempts to import from a specific directory.
// It is a helper function that wraps tryPath with proper error handling.
func (i *SafeImporter) tryImport(dir, importedPath string) (jsonnet.Contents, string, bool, error) {
	found, contents, foundHere, err := i.tryPath(dir, importedPath)
	if err != nil {
		// Return error from tryPath directly, it's already wrapped.
		return jsonnet.Contents{}, "", false, err
	}

	return contents, foundHere, found, nil
}

// Import implements jsonnet.Importer interface.
// It searches for the importedPath in several locations in order:
//  1. Relative to the importing file (if importedFrom is provided)
//  2. In the root directory (if importedPath is not absolute)
//  3. In each of the JPaths
//
// The method respects the security boundary and will not allow imports from outside
// the root directory.
func (i *SafeImporter) Import(importedFrom, importedPath string) (jsonnet.Contents, string, error) {
	// Try relative to importing file
	if importedFrom != "" && !filepath.IsAbs(importedPath) {
		relDir, err := i.getRelativeDir(importedFrom)
		if err != nil {
			return jsonnet.Contents{}, "", err
		}

		contents, foundHere, found, err := i.tryImport(relDir, importedPath)
		if err != nil {
			return jsonnet.Contents{}, "", err
		}
		if found {
			return contents, foundHere, nil
		}
	} else if !filepath.IsAbs(importedPath) {
		// Try from root directory
		contents, foundHere, found, err := i.tryImport(".", importedPath)
		if err != nil {
			return jsonnet.Contents{}, "", err
		}
		if found {
			return contents, foundHere, nil
		}
	}

	// Try each library path
	for _, jpath := range i.JPaths {
		contents, foundHere, found, err := i.tryImport(jpath, importedPath)
		if err != nil {
			return jsonnet.Contents{}, "", err
		}
		if found {
			return contents, foundHere, nil
		}
	}

	return jsonnet.Contents{}, "", ErrFileNotFound
}

// Close releases resources associated with the importer.
// This should be called when the importer is no longer needed to prevent resource leaks.
func (i *SafeImporter) Close() error {
	if i.root != nil {
		err := i.root.Close()
		if err != nil {
			// Wrap the error from Close using the new sentinel error
			return fmt.Errorf("%w: %q: %w", ErrCloseRootDir, i.root.Name(), err)
		}
	}

	return nil
}

// isSubpath returns true if sub is a subdirectory of parent.
// This is used to verify that paths remain within the security boundary.
// parent and sub are expected to be absolute paths.
func isSubpath(parent, sub string) bool {
	parent = filepath.Clean(parent)
	sub = filepath.Clean(sub)

	return parent == sub || (len(sub) > len(parent) &&
		sub[:len(parent)] == parent &&
		sub[len(parent)] == filepath.Separator)
}
