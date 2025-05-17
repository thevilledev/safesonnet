package safesonnet

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
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

	// Convert JPaths to be relative to root if needed
	cleanJPaths := make([]string, 0, len(jpaths))
	rootAbs, err := filepath.Abs(rootDir)
	if err != nil {
		root.Close()

		return nil, fmt.Errorf("%w for rootDir %q: %w", ErrAbsPath, rootDir, err)
	}

	for _, jpath := range jpaths {
		if jpath == "" {
			continue
		}

		// Explicitly check for null bytes in jpath, as these are invalid in paths.
		if strings.Contains(jpath, "\x00") {
			root.Close()

			return nil, fmt.Errorf("%w: jpath %q", ErrInvalidNullByte, jpath)
		}

		var absJPathCandidate string
		if filepath.IsAbs(jpath) {
			absJPathCandidate = filepath.Clean(jpath)
		} else {
			// If jpath is relative, it must be joined with rootAbs to make it absolute
			// *within the context of the rootDir*.
			absJPathCandidate = filepath.Join(rootAbs, jpath)
		}

		// Ensure path is within root
		if !isSubpath(rootAbs, absJPathCandidate) {
			root.Close()

			return nil, fmt.Errorf(
				"%w: jpath %q (interpreted as %q) is outside root directory %q (resolved to %q)",
				ErrJPathOutsideRoot,
				jpath,
				absJPathCandidate,
				rootDir,
				rootAbs,
			)
		}
		// Convert to root-relative path
		relPath, err := filepath.Rel(rootAbs, absJPathCandidate)
		if err != nil {
			root.Close()

			return nil, fmt.Errorf(
				"%w for jpath %q (interpreted as %q) relative to root %q (resolved to %q): %w",
				ErrRelPath,
				jpath,
				absJPathCandidate,
				rootDir,
				rootAbs,
				err,
			)
		}
		cleanJPaths = append(cleanJPaths, relPath)
	}

	// If no JPaths provided, use root as the only path
	if len(cleanJPaths) == 0 {
		cleanJPaths = []string{"."}
	}

	si := &SafeImporter{
		JPaths:      cleanJPaths,
		root:        root,
		rootAbsPath: rootAbs,                                       // Store the absolute root path
		logger:      log.New(io.Discard, "[safesonnet-debug] ", 0), // Default to silent
	}

	for _, opt := range opts {
		opt(si)
	}

	return si, nil
}

// normalizeCacheKey converts the cache key to lowercase on OSes that typically
// have case-insensitive file systems. This helps prevent duplicate cache entries
// for the same file accessed with different casings.
// This is a heuristic and might not cover all edge cases of file system configurations.
func normalizeCacheKey(path string) string {
	switch runtime.GOOS {
	case "windows", "darwin":
		return strings.ToLower(path)
	default:
		return path
	}
}

// tryPath attempts to import a file from the root directory.
// It handles caching of file contents and existence checks using sync.Map.
func (i *SafeImporter) tryPath(dir, importedPath string) (bool, jsonnet.Contents, string, error) {
	// Create a canonical logical path relative to the importer's root. This path is used for
	// consistent identification of the resource within the importer's context.
	var logicalPath string
	if filepath.IsAbs(importedPath) {
		logicalPath = importedPath // This branch is for caching the rejection of absolute import attempts.
	} else {
		logicalPath = filepath.Join(dir, importedPath)
	}
	logicalPath = filepath.Clean(logicalPath)

	cacheKey := normalizeCacheKey(logicalPath)

	// Check cache first using sync.Map Load
	if value, isCached := i.fsCache.Load(cacheKey); isCached {
		entry, ok := value.(*fsCacheEntry) // Assert type
		if !ok {
			// Handle unexpected type in cache - this indicates a programming
			// error or cache corruption.
			// Returning an error is safer than panicking.
			// Wrap the static error ErrCacheInternalType
			return false, jsonnet.Contents{}, "", fmt.Errorf(
				"%w for key %q", ErrCacheInternalType, cacheKey)
		}
		if !entry.exists {
			return false, jsonnet.Contents{}, "", nil
		}

		return true, entry.contents, logicalPath, nil
	}

	var relPathToOpen string
	// Handle absolute paths explicitly first for security checks and potential direct load
	if filepath.IsAbs(importedPath) {
		cleanedAbsImportedPath := filepath.Clean(importedPath)
		if !isSubpath(i.rootAbsPath, cleanedAbsImportedPath) {
			// Cache the negative result for this forbidden path
			i.fsCache.Store(cacheKey, &fsCacheEntry{exists: false})

			return false, jsonnet.Contents{}, "", fmt.Errorf(
				"%w: path %q (resolved to %q) is outside root directory %q",
				ErrForbiddenAbsolutePath,
				importedPath,
				cleanedAbsImportedPath,
				i.rootAbsPath,
			)
		}
		// It's an absolute path *within* the root. Attempt to load it relative to root.
		var err error
		relPathToOpen, err = filepath.Rel(i.rootAbsPath, cleanedAbsImportedPath)
		if err != nil {
			// Should not happen if isSubpath passed, but handle defensively.
			// Cache as not found to prevent re-evaluation of this problematic Rel call.
			i.fsCache.Store(cacheKey, &fsCacheEntry{exists: false})

			return false, jsonnet.Contents{}, "", fmt.Errorf(
				"internal error: failed to make absolute path %q relative to root %q: %w",
				cleanedAbsImportedPath,
				i.rootAbsPath,
				err,
			)
		}
	} else {
		// For relative paths, join with the search directory (which is relative to root).
		relPathToOpen = filepath.Clean(filepath.Join(dir, importedPath)) // Ensure it's clean for os.Root
	}

	f, err := i.root.Open(relPathToOpen)
	if err != nil {
		if os.IsNotExist(err) {
			// Path does not exist according to os.Root. Check if this was due to traversal outside root.
			effectiveFullPath := filepath.Clean(filepath.Join(i.rootAbsPath, dir, importedPath))
			if !isSubpath(i.rootAbsPath, effectiveFullPath) {
				// Cache the negative result for this forbidden path
				i.fsCache.Store(cacheKey, &fsCacheEntry{exists: false})

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
			i.fsCache.Store(cacheKey, &fsCacheEntry{exists: false})

			return false, jsonnet.Contents{}, "", nil
		}
		// Other error during Open (e.g., permission denied on an existing file within root)
		return false, jsonnet.Contents{}, "", fmt.Errorf("%w: %q: %w", ErrOpenFile, relPathToOpen, err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return false, jsonnet.Contents{}, "", fmt.Errorf("%w: %q: %w", ErrReadFile, relPathToOpen, err)
	}

	// Cache the positive result using sync.Map Store
	contents := jsonnet.MakeContents(string(data))
	i.fsCache.Store(cacheKey, &fsCacheEntry{
		exists:   true,
		contents: contents,
	})

	return true, contents, logicalPath, nil
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
		// For initial file loads, go-jsonnet provides importedPath which could be CWD-relative or absolute.
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

		// Check if this resolved absolute path is within our importer's root.
		if isSubpath(i.rootAbsPath, absEntrypointPath) {
			// It's inside the root. Make it relative to the root for os.Root access.
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

			contents, _, found, err := i.tryImport(".", pathForOsRoot) // dir is "." as pathForOsRoot is relative to jail root
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
			// If it was in root but tryImport failed to find it (e.g. a symlink loop within os.Root, or other rare FS issue)
			i.logger.Printf(
				"SafeImporter.Import: Initial file %q (abs: %q, pathForOsRoot: %q) was IN ROOT but NOT FOUND by tryImport.",
				importedPath,
				absEntrypointPath,
				pathForOsRoot,
			)
			// Fall through to JPath search for this specific case if desired, or return error.
			// For now, if it was in root and not found, assume it's a deeper issue or genuinely not there in the jail.
			// However, tests might expect JPath search even for initial files not at actual jail root.
			// To satisfy tests like `import_from_library_path` where entrypoint is in JPath:
			// we MUST fall through to JPath logic if not found by direct path resolution, even if `isSubpath` was true.
			i.logger.Printf(
				"SafeImporter.Import: Initial file (was in root) not found, falling through to JPath for path %q.",
				importedPath,
			)
		} else { // absEntrypointPath is OUTSIDE i.rootAbsPath
			// If the *original* path was absolute AND it's outside root, it's a firm error. No JPath search.
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
			// If original path was relative, but its CWD-absolute form is outside our root,
			// it means the CWD is not aligned with our root for this path.
			// We should then try to find `importedPath` (the original relative string) via JPaths.
			i.logger.Printf(
				"SafeImporter.Import: Initial path %q (abs: %q) is outside root. Falling through to JPath for path %q.",
				importedPath,
				absEntrypointPath,
				importedPath,
			)
		}
		// If we reach here for importedFrom == "", it means either:
		// - initial path (abs or rel) resolved to be IN root, but direct tryImport didn't find it
		//   -> try JPaths for original `importedPath`.
		// - initial path was RELATIVE, its abs form was OUTSIDE root -> try JPaths for original `importedPath`.
		// The JPath loop below will use the original `importedPath` string.
	} else { // importedFrom != "" (Regular import)
		if !filepath.IsAbs(importedPath) {
			relDir, err := i.getRelativeDir(importedFrom)
			if err != nil {
				return jsonnet.Contents{}, "", err
			}
			contents, foundAtLogicFromTryPath, found, err := i.tryImport(relDir, importedPath)
			if err != nil {
				return jsonnet.Contents{}, "", err
			}
			if found {
				finalFoundAt := foundAtLogicFromTryPath
				if !filepath.IsAbs(finalFoundAt) {
					finalFoundAt = filepath.Join(i.rootAbsPath, finalFoundAt)
				}

				return contents, filepath.Clean(finalFoundAt), nil
			}
		} else { // importedPath is ABSOLUTE (and importedFrom is not empty)
			i.logger.Printf(
				"SafeImporter.Import: Absolute importPath %q from %q. Passing to tryImport.",
				importedPath,
				importedFrom,
			)
			contents, foundAtLogicFromTryPath, found, err := i.tryImport(".", importedPath)
			if err != nil {
				return jsonnet.Contents{}, "", err
			}
			if found {
				finalFoundAt := foundAtLogicFromTryPath
				if !filepath.IsAbs(finalFoundAt) {
					finalFoundAt = filepath.Join(i.rootAbsPath, finalFoundAt)
				}

				return contents, filepath.Clean(finalFoundAt), nil
			}
		}
		// If a regular import (relative or absolute) is not found by the specific attempts above, it will fall to JPaths.
	}

	// Fallback to JPaths for:
	// 1. Initial files (importedFrom == "") if not resolved by direct absolute path logic above.
	// 2. Regular imports (importedFrom != "") if not found by relative-to-importing-file or direct absolute path logic.
	i.logger.Printf(
		"SafeImporter.Import: Falling back to JPaths to find %q (original importedPath) from context of %q",
		importedPath,
		importedFrom,
	)

	searchPaths := i.JPaths
	// For an initial file load that falls through to JPath search, ensure "." (the rootDir itself) is considered.
	// This helps align with go-jsonnet behavior where an entrypoint might be in a JPath,
	// including the implicit current dir.
	if importedFrom == "" {
		hasDot := false
		for _, p := range i.JPaths {
			if p == "." {
				hasDot = true

				break
			}
		}
		if !hasDot {
			// Prepend "." to a temporary slice to avoid modifying i.JPaths
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
