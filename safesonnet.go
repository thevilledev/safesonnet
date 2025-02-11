package safesonnet

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/go-jsonnet"
)

// SafeImporter implements jsonnet.Importer interface that restricts imports to a specific directory
type SafeImporter struct {
	JPaths  []string // Library search paths within the root
	root    *os.Root
	fsCache map[string]*fsCacheEntry
}

type fsCacheEntry struct {
	contents jsonnet.Contents
	exists   bool
}

// NewSafeImporter creates a new SafeImporter that restricts imports to the given directory
func NewSafeImporter(rootDir string, jpaths []string) (*SafeImporter, error) {
	if rootDir == "" {
		return nil, fmt.Errorf("root directory must not be empty")
	}

	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open root directory %q: %w", rootDir, err)
	}

	// Convert JPaths to be relative to root if needed
	cleanJPaths := make([]string, 0, len(jpaths))
	rootAbs, err := filepath.Abs(rootDir)
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("failed to get absolute path of root: %w", err)
	}

	for _, jpath := range jpaths {
		if jpath == "" {
			continue
		}
		// Convert to absolute path
		absPath, err := filepath.Abs(jpath)
		if err != nil {
			root.Close()
			return nil, fmt.Errorf("failed to get absolute path of jpath %q: %w", jpath, err)
		}
		// Ensure path is within root
		if !isSubpath(rootAbs, absPath) {
			root.Close()
			return nil, fmt.Errorf("jpath %q is outside root directory", jpath)
		}
		// Convert to root-relative path
		relPath, err := filepath.Rel(rootAbs, absPath)
		if err != nil {
			root.Close()
			return nil, fmt.Errorf("failed to get relative path of jpath %q: %w", jpath, err)
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

// tryPath attempts to import a file from the root directory
func (i *SafeImporter) tryPath(dir, importedPath string) (found bool, contents jsonnet.Contents, foundHere string, err error) {
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
	} else {
		// For relative paths, join with the search directory
		relPath = filepath.Join(dir, importedPath)
	}

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

	contents = jsonnet.MakeContents(string(data))
	i.fsCache[absPath] = &fsCacheEntry{
		exists:   true,
		contents: contents,
	}

	return true, contents, absPath, nil
}

// Import implements jsonnet.Importer interface
func (i *SafeImporter) Import(importedFrom, importedPath string) (contents jsonnet.Contents, foundAt string, err error) {
	// If we're importing from a file, first try relative to that file
	if importedFrom != "" && !filepath.IsAbs(importedPath) {
		// Convert importedFrom to be relative to root if it's absolute
		var relDir string
		if filepath.IsAbs(importedFrom) {
			rootName := i.root.Name()
			rootAbs, err := filepath.Abs(rootName)
			if err != nil {
				return jsonnet.Contents{}, "", fmt.Errorf("failed to get root absolute path: %w", err)
			}
			relDir, err = filepath.Rel(rootAbs, filepath.Dir(importedFrom))
			if err != nil {
				return jsonnet.Contents{}, "", fmt.Errorf("failed to get relative path: %w", err)
			}
		} else {
			relDir = filepath.Dir(importedFrom)
		}

		found, contents, foundHere, err := i.tryPath(relDir, importedPath)
		if err != nil {
			return jsonnet.Contents{}, "", fmt.Errorf("failed to read file: %w", err)
		}
		if found {
			return contents, foundHere, nil
		}
	} else if !filepath.IsAbs(importedPath) {
		// If importing from root, try root directory first
		found, contents, foundHere, err := i.tryPath(".", importedPath)
		if err != nil {
			return jsonnet.Contents{}, "", fmt.Errorf("failed to read file: %w", err)
		}
		if found {
			return contents, foundHere, nil
		}
	}

	// Try each library path in order
	for _, jpath := range i.JPaths {
		found, contents, foundHere, err := i.tryPath(jpath, importedPath)
		if err != nil {
			return jsonnet.Contents{}, "", fmt.Errorf("failed to read file: %w", err)
		}
		if found {
			return contents, foundHere, nil
		}
	}

	return jsonnet.Contents{}, "", fmt.Errorf("file not found in any library path")
}

// Close releases resources associated with the importer
func (i *SafeImporter) Close() error {
	if i.root != nil {
		return i.root.Close()
	}
	return nil
}

// isSubpath returns true if sub is a subdirectory of parent
func isSubpath(parent, sub string) bool {
	parent = filepath.Clean(parent)
	sub = filepath.Clean(sub)
	return parent == sub || sub == "." || (len(sub) > len(parent) && sub[:len(parent)] == parent && sub[len(parent)] == filepath.Separator)
}
