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
	// ErrForbiddenAbsolutePath is returned when an import path is absolute and outside the
	// root directory.
	ErrForbiddenAbsolutePath = errors.New("forbidden absolute import path")
	// ErrForbiddenRelativePathTraversal is returned when a relative import path attempts to
	// traverse outside the root directory.
	ErrForbiddenRelativePathTraversal = errors.New("forbidden relative import path traversal")
	// ErrInvalidNullByte is returned when a path contains a null byte, which is invalid.
	ErrInvalidNullByte = errors.New("path contains an invalid null byte")
)

// SafeImporter implements jsonnet.Importer interface that restricts imports to a specific directory.
// It prevents path traversal attacks by ensuring all imports are within the specified root directory.
// The importer supports a list of library paths (JPaths) within the root directory,
// similar to the standard jsonnet importer. Caches file reads.
type SafeImporter struct {
	// JPaths is a list of library search paths within the root directory.
	JPaths      []string
	root        *os.Root
	fsCache     sync.Map
	rootAbsPath string // Absolute path to the root directory
	logger      *log.Logger
}

type fsCacheEntry struct {
	contents jsonnet.Contents
	exists   bool
}

// Option is a functional option for configuring SafeImporter.
type Option func(*SafeImporter)

// WithLogger allows providing a custom logger to SafeImporter.
// If nil is provided, the default discarding logger will be used.
func WithLogger(logger *log.Logger) Option {
	return func(si *SafeImporter) {
		if logger != nil {
			si.logger = logger
		}
	}
}

// NewSafeImporter creates a new SafeImporter that restricts imports to the given directory.
// It validates that all provided JPaths are within the root directory to maintain
// the security boundary. If no JPaths are provided, the root directory is used as
// the only search path.
//
// rootDir must be a valid directory path or an error will be returned.
// jpaths should be a list of directories inside rootDir to search for imports.
// opts can be used to configure the SafeImporter, e.g., by providing a logger.
func NewSafeImporter(rootDir string, jpaths []string, opts ...Option) (*SafeImporter, error) {
	if rootDir == "" {
		return nil, ErrEmptyRootDir
	}

	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrOpenRootDir, rootDir, err)
	}

	rootAbs, err := filepath.Abs(rootDir)
	if err != nil {
		root.Close()

		return nil, fmt.Errorf("%w for rootDir %q: %w", ErrAbsPath, rootDir, err)
	}

	// Convert JPaths to be relative to root if needed
	cleanJPaths, err := processJPaths(jpaths, rootAbs, root)
	if err != nil {
		return nil, err
	}

	si := &SafeImporter{
		JPaths:      cleanJPaths,
		root:        root,
		rootAbsPath: rootAbs,
		logger:      log.New(io.Discard, "[safesonnet-debug] ", 0), // Default to silent
	}

	for _, opt := range opts {
		opt(si)
	}

	return si, nil
}

// processJPaths validates and processes the provided JPaths, ensuring they are within the root directory.
func processJPaths(jpaths []string, rootAbs string, root *os.Root) ([]string, error) {
	cleanJPaths := make([]string, 0, len(jpaths))

	for _, jpath := range jpaths {
		if jpath == "" {
			continue
		}

		processedPath, err := processSingleJPath(jpath, rootAbs, root)
		if err != nil {
			return nil, err
		}

		cleanJPaths = append(cleanJPaths, processedPath)
	}

	// If no JPaths provided, use root as the only path
	if len(cleanJPaths) == 0 {
		cleanJPaths = []string{"."}
	}

	return cleanJPaths, nil
}

// processSingleJPath validates and processes a single JPath entry.
func processSingleJPath(jpath, rootAbs string, root *os.Root) (string, error) {
	// Explicitly check for null bytes in jpath, as these are invalid in paths.
	if strings.Contains(jpath, "\x00") {
		root.Close()

		return "", fmt.Errorf("%w: jpath %q", ErrInvalidNullByte, jpath)
	}

	absJPathCandidate := resolveJPathToAbsolute(jpath, rootAbs)

	// Ensure path is within root
	if !isSubpath(rootAbs, absJPathCandidate) {
		root.Close()

		return "", fmt.Errorf(
			"%w: jpath %q (interpreted as %q) is outside root directory %q (resolved to %q)",
			ErrJPathOutsideRoot,
			jpath,
			absJPathCandidate,
			root.Name(),
			rootAbs,
		)
	}

	// Convert to root-relative path
	relPath, err := filepath.Rel(rootAbs, absJPathCandidate)
	if err != nil {
		root.Close()

		return "", fmt.Errorf(
			"%w for jpath %q (interpreted as %q) relative to root %q (resolved to %q): %w",
			ErrRelPath,
			jpath,
			absJPathCandidate,
			root.Name(),
			rootAbs,
			err,
		)
	}

	return relPath, nil
}

// resolveJPathToAbsolute converts a JPath to its absolute form.
func resolveJPathToAbsolute(jpath, rootAbs string) string {
	if filepath.IsAbs(jpath) {
		return filepath.Clean(jpath)
	}

	// If jpath is relative, it must be joined with rootAbs to make it absolute
	// *within the context of the rootDir*.
	return filepath.Join(rootAbs, jpath)
}

// tryPath attempts to import a file from the root directory.
// It handles caching of file contents and existence checks using sync.Map.
func (i *SafeImporter) tryPath(dir, importedPath string) (bool, jsonnet.Contents, string, error) {
	logicalPath := i.createLogicalPath(dir, importedPath)

	// Check cache first
	if found, contents, err := i.checkCache(logicalPath); err != nil || found != nil {
		if err != nil {
			return false, jsonnet.Contents{}, "", err
		}
		if !*found {
			return false, jsonnet.Contents{}, "", nil
		}

		return true, contents, logicalPath, nil
	}

	// Determine the path to open relative to root
	relPathToOpen, err := i.resolvePathToOpen(dir, importedPath, logicalPath)
	if err != nil {
		return false, jsonnet.Contents{}, "", err
	}

	// Attempt to open and read the file
	return i.openAndReadFile(relPathToOpen, logicalPath)
}

// createLogicalPath creates a canonical logical path for caching purposes.
func (i *SafeImporter) createLogicalPath(dir, importedPath string) string {
	var logicalPath string
	if filepath.IsAbs(importedPath) {
		logicalPath = importedPath // This branch is for caching the rejection of absolute import attempts.
	} else {
		logicalPath = filepath.Join(dir, importedPath)
	}

	return filepath.Clean(logicalPath)
}

// checkCache checks if the file is already cached and returns the result.
// Returns (found, contents, error) where found is nil if not cached, otherwise *bool indicating if file exists.
func (i *SafeImporter) checkCache(logicalPath string) (*bool, jsonnet.Contents, error) {
	value, isCached := i.fsCache.Load(logicalPath)
	if !isCached {
		return nil, jsonnet.Contents{}, nil
	}

	entry, ok := value.(*fsCacheEntry)
	if !ok {
		return nil, jsonnet.Contents{}, fmt.Errorf(
			"%w for key %q", ErrCacheInternalType, logicalPath)
	}

	found := entry.exists

	return &found, entry.contents, nil
}

// resolvePathToOpen determines the actual path to open relative to the root directory.
func (i *SafeImporter) resolvePathToOpen(dir, importedPath, logicalPath string) (string, error) {
	if filepath.IsAbs(importedPath) {
		return i.handleAbsolutePathResolution(importedPath, logicalPath)
	}

	// For relative paths, join with the search directory (which is relative to root).
	return filepath.Clean(filepath.Join(dir, importedPath)), nil
}

// handleAbsolutePathResolution processes absolute paths with security checks.
func (i *SafeImporter) handleAbsolutePathResolution(importedPath, logicalPath string) (string, error) {
	cleanedAbsImportedPath := filepath.Clean(importedPath)
	if !isSubpath(i.rootAbsPath, cleanedAbsImportedPath) {
		// Cache the negative result for this forbidden path
		i.fsCache.Store(logicalPath, &fsCacheEntry{exists: false})

		return "", fmt.Errorf(
			"%w: path %q (resolved to %q) is outside root directory %q",
			ErrForbiddenAbsolutePath,
			importedPath,
			cleanedAbsImportedPath,
			i.rootAbsPath,
		)
	}

	// It's an absolute path *within* the root. Attempt to load it relative to root.
	relPathToOpen, err := filepath.Rel(i.rootAbsPath, cleanedAbsImportedPath)
	if err != nil {
		// Should not happen if isSubpath passed, but handle defensively.
		// Cache as not found to prevent re-evaluation of this problematic Rel call.
		i.fsCache.Store(logicalPath, &fsCacheEntry{exists: false})

		return "", fmt.Errorf(
			"internal error: failed to make absolute path %q relative to root %q: %w",
			cleanedAbsImportedPath,
			i.rootAbsPath,
			err,
		)
	}

	return relPathToOpen, nil
}

// openAndReadFile attempts to open and read the file, handling errors and caching results.
func (i *SafeImporter) openAndReadFile(relPathToOpen, logicalPath string) (bool, jsonnet.Contents, string, error) {
	f, err := i.root.Open(relPathToOpen)
	if err != nil {
		return i.handleOpenError(err, relPathToOpen, logicalPath)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return false, jsonnet.Contents{}, "", fmt.Errorf("%w: %q: %w", ErrReadFile, relPathToOpen, err)
	}

	// Cache the positive result
	contents := jsonnet.MakeContents(string(data))
	i.fsCache.Store(logicalPath, &fsCacheEntry{
		exists:   true,
		contents: contents,
	})

	return true, contents, logicalPath, nil
}

// handleOpenError processes errors from opening files, including path traversal checks.
func (i *SafeImporter) handleOpenError(err error, relPathToOpen, logicalPath string) (
	bool, jsonnet.Contents, string, error) {
	if !os.IsNotExist(err) {
		// Other error during Open (e.g., permission denied on an existing file within root)
		return false, jsonnet.Contents{}, "", fmt.Errorf("%w: %q: %w", ErrOpenFile, relPathToOpen, err)
	}

	// Path does not exist - check if this was due to traversal outside root
	return i.handleNotExistError(logicalPath)
}

// handleNotExistError handles file not found errors with security checks.
func (i *SafeImporter) handleNotExistError(logicalPath string) (bool, jsonnet.Contents, string, error) {
	// Extract the directory and imported path from the logical path for security check
	dir := filepath.Dir(logicalPath)
	importedPath := filepath.Base(logicalPath)

	// If the logical path is absolute, we need different handling
	if filepath.IsAbs(logicalPath) {
		// For absolute paths, we already checked security in handleAbsolutePathResolution
		// This is a genuine "not found" case
		i.fsCache.Store(logicalPath, &fsCacheEntry{exists: false})

		return false, jsonnet.Contents{}, "", nil
	}

	effectiveFullPath := filepath.Clean(filepath.Join(i.rootAbsPath, dir, importedPath))
	if !isSubpath(i.rootAbsPath, effectiveFullPath) {
		// Cache the negative result for this forbidden path
		i.fsCache.Store(logicalPath, &fsCacheEntry{exists: false})

		return false, jsonnet.Contents{}, "", fmt.Errorf(
			"%w: path %q (in search dir %q, resolved to %q) would be outside root directory %q",
			ErrForbiddenRelativePathTraversal,
			importedPath,
			dir,
			effectiveFullPath,
			i.rootAbsPath,
		)
	}

	// It's a genuine "not found" within the allowed scope.
	i.fsCache.Store(logicalPath, &fsCacheEntry{exists: false})

	return false, jsonnet.Contents{}, "", nil
}

// getRelativeDir returns the directory that importedFrom is in, relative to the importer's root.
// This helps resolve relative imports when importing from another file.
func (i *SafeImporter) getRelativeDir(importedFrom string) (string, error) {
	// Explicitly check for null bytes in importedFrom
	if strings.Contains(importedFrom, "\x00") {
		return "", fmt.Errorf("%w: importedFrom %q", ErrInvalidNullByte, importedFrom)
	}

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
	i.logger.Printf(
		"SafeImporter.Import CALLED: importedFrom=%q, importedPath=%q, jpaths=%v, rootDir=%q, rootAbsPath=%q",
		importedFrom,
		importedPath,
		i.JPaths,
		i.root.Name(),
		i.rootAbsPath,
	)

	if importedFrom == "" {
		return i.handleInitialImport(importedPath)
	}

	// Handle regular imports (importedFrom != "")
	contents, foundAt, found, err := i.handleRegularImport(importedFrom, importedPath)
	if err != nil {
		return jsonnet.Contents{}, "", err
	}
	if found {
		return contents, foundAt, nil
	}

	// Fallback to JPaths
	return i.searchInJPaths(importedFrom, importedPath)
}

// handleInitialImport processes initial file loads when importedFrom is empty.
func (i *SafeImporter) handleInitialImport(importedPath string) (jsonnet.Contents, string, error) {
	originalImportedPathIsAbs := filepath.IsAbs(importedPath)
	absEntrypointPath, err := filepath.Abs(importedPath)
	if err != nil {
		i.logger.Printf(
			"SafeImporter.Import: Error resolving initial path %q to absolute: %v",
			importedPath,
			err,
		)

		return jsonnet.Contents{}, "", fmt.Errorf(
			"error resolving initial path %q to absolute: %w",
			importedPath,
			err,
		)
	}

	i.logger.Printf(
		"SafeImporter.Import: Initial file. Original path %q (isAbs: %t) resolved to absolute %q",
		importedPath,
		originalImportedPathIsAbs,
		absEntrypointPath,
	)

	if isSubpath(i.rootAbsPath, absEntrypointPath) {
		return i.handleInitialImportInRoot(importedPath, absEntrypointPath)
	}

	return i.handleInitialImportOutsideRoot(importedPath, absEntrypointPath, originalImportedPathIsAbs)
}

// handleInitialImportInRoot processes initial imports that are within the root directory.
func (i *SafeImporter) handleInitialImportInRoot(
	importedPath, absEntrypointPath string,
) (jsonnet.Contents, string, error) {
	pathForOsRoot, err := filepath.Rel(i.rootAbsPath, absEntrypointPath)
	if err != nil {
		i.logger.Printf(
			"SafeImporter.Import: Error making initial abs path %q relative to root %q: %v",
			absEntrypointPath,
			i.rootAbsPath,
			err,
		)

		return jsonnet.Contents{}, "", fmt.Errorf(
			"error making initial path %q relative to importer root: %w",
			absEntrypointPath,
			err,
		)
	}

	i.logger.Printf(
		"SafeImporter.Import: Initial file is IN ROOT. Path for os.Root is %q. Calling tryImport.",
		pathForOsRoot,
	)

	contents, _, found, err := i.tryImport(".", pathForOsRoot)
	if err != nil {
		i.logger.Printf(
			"SafeImporter.Import: Error from tryImport for initial file in root (pathForOsRoot %q): %v",
			pathForOsRoot,
			err,
		)

		return jsonnet.Contents{}, "", err
	}

	if found {
		i.logger.Printf(
			"SafeImporter.Import: Successfully imported initial file %q (was in root). Returning abs path: %q",
			importedPath,
			absEntrypointPath,
		)

		return contents, absEntrypointPath, nil
	}

	i.logger.Printf(
		"SafeImporter.Import: Initial file (was in root) not found, falling through to JPath for path %q.",
		importedPath,
	)

	// Fall through to JPath search
	return i.searchInJPaths("", importedPath)
}

// handleInitialImportOutsideRoot processes initial imports that are outside the root directory.
func (i *SafeImporter) handleInitialImportOutsideRoot(
	importedPath, absEntrypointPath string, originalImportedPathIsAbs bool,
) (jsonnet.Contents, string, error) {
	if originalImportedPathIsAbs {
		i.logger.Printf(
			"SafeImporter.Import: Initial *originally absolute* path %q (abs: %q) is outside sandboxed root %q. Firm error.",
			importedPath,
			absEntrypointPath,
			i.rootAbsPath,
		)

		return jsonnet.Contents{}, "", fmt.Errorf(
			"%w: initial absolute path %q is outside importer root %q",
			ErrForbiddenAbsolutePath,
			importedPath,
			i.rootAbsPath,
		)
	}

	i.logger.Printf(
		"SafeImporter.Import: Initial path %q (abs: %q) is outside root. Falling through to JPath for path %q.",
		importedPath,
		absEntrypointPath,
		importedPath,
	)

	// Fall through to JPath search
	return i.searchInJPaths("", importedPath)
}

// handleRegularImport processes regular imports when importedFrom is not empty.
func (i *SafeImporter) handleRegularImport(importedFrom, importedPath string) (jsonnet.Contents, string, bool, error) {
	if !filepath.IsAbs(importedPath) {
		return i.handleRelativeImport(importedFrom, importedPath)
	}

	return i.handleAbsoluteImport(importedFrom, importedPath)
}

// handleRelativeImport processes relative imports.
func (i *SafeImporter) handleRelativeImport(importedFrom, importedPath string) (jsonnet.Contents, string, bool, error) {
	relDir, err := i.getRelativeDir(importedFrom)
	if err != nil {
		return jsonnet.Contents{}, "", false, err
	}

	contents, foundAtLogicFromTryPath, found, err := i.tryImport(relDir, importedPath)
	if err != nil {
		return jsonnet.Contents{}, "", false, err
	}

	if found {
		finalFoundAt := foundAtLogicFromTryPath
		if !filepath.IsAbs(finalFoundAt) {
			finalFoundAt = filepath.Join(i.rootAbsPath, finalFoundAt)
		}

		return contents, filepath.Clean(finalFoundAt), true, nil
	}

	return jsonnet.Contents{}, "", false, nil
}

// handleAbsoluteImport processes absolute imports.
func (i *SafeImporter) handleAbsoluteImport(importedFrom, importedPath string) (jsonnet.Contents, string, bool, error) {
	i.logger.Printf(
		"SafeImporter.Import: Absolute importPath %q from %q. Passing to tryImport.",
		importedPath,
		importedFrom,
	)

	contents, foundAtLogicFromTryPath, found, err := i.tryImport(".", importedPath)
	if err != nil {
		return jsonnet.Contents{}, "", false, err
	}

	if found {
		finalFoundAt := foundAtLogicFromTryPath
		if !filepath.IsAbs(finalFoundAt) {
			finalFoundAt = filepath.Join(i.rootAbsPath, finalFoundAt)
		}

		return contents, filepath.Clean(finalFoundAt), true, nil
	}

	return jsonnet.Contents{}, "", false, nil
}

// searchInJPaths searches for the imported file in the JPath directories.
func (i *SafeImporter) searchInJPaths(importedFrom, importedPath string) (jsonnet.Contents, string, error) {
	i.logger.Printf(
		"SafeImporter.Import: Falling back to JPaths to find %q (original importedPath) from context of %q",
		importedPath,
		importedFrom,
	)

	searchPaths := i.getEffectiveSearchPaths(importedFrom)

	for _, jpath := range searchPaths {
		contents, foundAtLogicFromTryPath, found, err := i.tryImport(jpath, importedPath)
		if err != nil {
			return jsonnet.Contents{}, "", err
		}

		if found {
			finalFoundAt := foundAtLogicFromTryPath
			if !filepath.IsAbs(finalFoundAt) {
				finalFoundAt = filepath.Join(i.rootAbsPath, finalFoundAt)
			}
			currentFoundAt := filepath.Clean(finalFoundAt)
			i.logger.Printf(
				"SafeImporter.Import: Found %q in JPath %q (effective). Returning abs path: %q",
				importedPath,
				jpath,
				currentFoundAt,
			)

			return contents, currentFoundAt, nil
		}
	}

	i.logger.Printf(
		"SafeImporter.Import: Failed to find %q from %q after all attempts. Returning ErrFileNotFound.",
		importedPath,
		importedFrom,
	)

	return jsonnet.Contents{}, "", ErrFileNotFound
}

// getEffectiveSearchPaths returns the search paths to use, potentially
// prepending "." for initial imports.
func (i *SafeImporter) getEffectiveSearchPaths(importedFrom string) []string {
	searchPaths := i.JPaths

	// For initial file loads, ensure "." is considered
	if importedFrom == "" {
		hasDot := false
		for _, p := range i.JPaths {
			if p == "." {
				hasDot = true

				break
			}
		}

		if !hasDot {
			tempSearchPaths := make([]string, 0, len(i.JPaths)+1)
			tempSearchPaths = append(tempSearchPaths, ".")
			tempSearchPaths = append(tempSearchPaths, i.JPaths...)
			searchPaths = tempSearchPaths
			i.logger.Printf(
				"SafeImporter.Import: For initial file, prepended \".\" to JPaths. Effective search: %v",
				searchPaths,
			)
		}
	}

	return searchPaths
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
