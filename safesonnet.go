package safesonnet

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

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
	// ErrRootAbsPath is returned when the root absolute path cannot be obtained.
	ErrRootAbsPath = errors.New("failed to get root absolute path")
	// ErrRelPathConversion is returned when a relative path cannot be obtained.
	ErrRelPathConversion = errors.New("failed to get relative path")
	// ErrFileNotFound is returned when a file is not found in any library path.
	ErrFileNotFound = errors.New("file not found in any library path")
)

// SafeImporter implements jsonnet.Importer interface that restricts imports to a specific directory.
type SafeImporter struct {
	JPaths  []string // Library search paths within the root
	root    *os.Root
	fsCache map[string]*fsCacheEntry
}

type fsCacheEntry struct {
	contents jsonnet.Contents
	exists   bool
}

// NewSafeImporter creates a new SafeImporter that restricts imports to the given directory.
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
		JPaths:  cleanJPaths,
		root:    root,
		fsCache: make(map[string]*fsCacheEntry),
	}, nil
}

// tryPath attempts to import a file from the root directory.
func (i *SafeImporter) tryPath(dir, importedPath string) (bool, jsonnet.Contents, string, error) {
	// Create absolute path for cache key
	var absPath string
	if filepath.IsAbs(importedPath) {
		absPath = importedPath
	} else {
		absPath = filepath.Join(dir, importedPath)
	}

	// Check cache first
	if entry, isCached := i.fsCache[absPath]; isCached {
		if !entry.exists {
			return false, jsonnet.Contents{}, "", nil
		}

		return true, entry.contents, absPath, nil
	}

	// Try to open and read the file
	var relPath string
	if filepath.IsAbs(importedPath) {
		// Absolute paths are not allowed
		i.fsCache[absPath] = &fsCacheEntry{exists: false}

		return false, jsonnet.Contents{}, "", nil
	}

	// For relative paths, join with the search directory
	relPath = filepath.Join(dir, importedPath)

	// Clean the path to remove any . or .. components
	relPath = filepath.Clean(relPath)

	f, err := i.root.Open(relPath)
	if err != nil {
		if os.IsNotExist(err) {
			i.fsCache[absPath] = &fsCacheEntry{exists: false}

			return false, jsonnet.Contents{}, "", nil
		}

		return false, jsonnet.Contents{}, "", err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return false, jsonnet.Contents{}, "", err
	}

	contents := jsonnet.MakeContents(string(data))
	i.fsCache[absPath] = &fsCacheEntry{
		exists:   true,
		contents: contents,
	}

	return true, contents, absPath, nil
}

// getRelativeDir returns the directory that importedFrom is in, relative to the importer's root.
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
func (i *SafeImporter) tryImport(dir, importedPath string) (jsonnet.Contents, string, bool, error) {
	found, contents, foundHere, err := i.tryPath(dir, importedPath)
	if err != nil {
		return jsonnet.Contents{}, "", false, fmt.Errorf("%w: %w", ErrReadFile, err)
	}

	return contents, foundHere, found, nil
}

// Import implements jsonnet.Importer interface.
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
func (i *SafeImporter) Close() error {
	if i.root != nil {
		return i.root.Close()
	}

	return nil
}

// isSubpath returns true if sub is a subdirectory of parent.
func isSubpath(parent, sub string) bool {
	parent = filepath.Clean(parent)
	sub = filepath.Clean(sub)

	return parent == sub || sub == "." || (len(sub) > len(parent) &&
		sub[:len(parent)] == parent &&
		sub[len(parent)] == filepath.Separator)
}
