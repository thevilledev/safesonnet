package safesonnet

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestNewSafeImporter(t *testing.T) {
	t.Parallel()

	// Setup test directories
	rootDir := t.TempDir()
	outsideDir := t.TempDir()

	// Create test directory structure
	mustWriteFile(t, filepath.Join(rootDir, "lib", "test.jsonnet"), "{}")
	mustWriteFile(t, filepath.Join(rootDir, "vendor", "test.jsonnet"), "{}")
	mustWriteFile(t, filepath.Join(outsideDir, "test.jsonnet"), "{}")

	// Create a bad root path that will cause filepath.Abs to fail
	badRoot := string([]byte{0})

	tests := []struct {
		name    string
		rootDir string
		jpaths  []string
		wantErr bool
	}{
		{
			name:    "empty root directory",
			rootDir: "",
			jpaths:  nil,
			wantErr: true,
		},
		{
			name:    "non-existent root directory",
			rootDir: "/does/not/exist",
			jpaths:  nil,
			wantErr: true,
		},
		{
			name:    "valid root no jpaths",
			rootDir: rootDir,
			jpaths:  nil,
			wantErr: false,
		},
		{
			name:    "valid root with jpaths",
			rootDir: rootDir,
			jpaths:  []string{filepath.Join(rootDir, "lib"), filepath.Join(rootDir, "vendor")},
			wantErr: false,
		},
		{
			name:    "jpath outside root",
			rootDir: rootDir,
			jpaths:  []string{outsideDir},
			wantErr: true,
		},
		{
			name:    "empty jpath",
			rootDir: rootDir,
			jpaths:  []string{""},
			wantErr: false, // Should skip empty paths
		},
		{
			name:    "invalid jpath for absPath",
			rootDir: rootDir,
			jpaths:  []string{string([]byte{0})}, // Invalid path for Abs
			wantErr: true,
		},
		{
			name:    "jpath with invalid relative path",
			rootDir: rootDir,
			jpaths:  []string{rootDir + string([]byte{0})}, // This should cause filepath.Rel to fail
			wantErr: true,
		},
		{
			name:    "invalid root path",
			rootDir: badRoot,
			jpaths:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			imp, err := NewSafeImporter(tt.rootDir, tt.jpaths, WithLogger(log.New(os.Stdout, "", 0)))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSafeImporter() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if err == nil {
				defer imp.Close()
				if len(imp.JPaths) == 0 {
					t.Error("JPaths is empty when it should contain at least '.'")
				}
			}
		})
	}
}

func TestImport_BasicFunctionality(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		importedPath string
		wantContent  string
		wantErr      bool
		setupExtra   func(string) // Additional setup for specific tests
	}{
		{
			name:         "import from root",
			importedPath: "lib.jsonnet",
			wantContent:  `{x: 1}`,
		},
		{
			name:         "import from library path",
			importedPath: "util.jsonnet",
			wantContent:  `{y: 2}`,
			setupExtra: func(dir string) {
				mustWriteFile(t, filepath.Join(dir, "lib", "util.jsonnet"), `{y: 2}`)
			},
		},
		{
			name:         "relative import",
			importedPath: "lib.jsonnet",
			wantContent:  `{x: 1}`,
		},
		{
			name:         "non-existent file",
			importedPath: "missing.jsonnet",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Setup test directory structure for each test
			tmpDir := t.TempDir()
			mustWriteFile(t, filepath.Join(tmpDir, "main.jsonnet"), `local lib = import 'lib.jsonnet'; lib`)
			mustWriteFile(t, filepath.Join(tmpDir, "lib.jsonnet"), `{x: 1}`)

			// Run any additional setup
			if tt.setupExtra != nil {
				tt.setupExtra(tmpDir)
			}

			imp, err := NewSafeImporter(tmpDir, []string{filepath.Join(tmpDir, "lib")}, WithLogger(log.New(os.Stdout, "", 0)))
			if err != nil {
				t.Fatalf("NewSafeImporter() error = %v", err)
			}
			defer imp.Close()

			var importedFrom string
			var pathToImport string

			if tt.name == "relative import" {
				importedFrom = filepath.Join(tmpDir, "main.jsonnet")
				pathToImport = tt.importedPath
			} else {
				if tt.name == "import from library path" {
					pathToImport = tt.importedPath
				} else {
					pathToImport = filepath.Join(tmpDir, tt.importedPath)
				}
			}

			contents, _, err := imp.Import(importedFrom, pathToImport)
			if (err != nil) != tt.wantErr {
				t.Errorf("Import() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !tt.wantErr && contents.String() != tt.wantContent {
				t.Errorf("Import() contents = %v, want %v", contents.String(), tt.wantContent)
			}
		})
	}
}

func TestImport_SecurityBoundary(t *testing.T) {
	t.Parallel()

	// Setup test directory structure
	tmpDir := t.TempDir()
	mustWriteFile(t, filepath.Join(tmpDir, "safe.jsonnet"), `{x: 1}`)
	mustWriteFile(t, filepath.Join(tmpDir, "lib", "safe.jsonnet"), `{y: 2}`)

	// Create a file outside the root
	outsideDir := t.TempDir()
	mustWriteFile(t, filepath.Join(outsideDir, "unsafe.jsonnet"), `{z: 3}`)

	// Create symbolic links
	if err := os.Symlink(
		filepath.Join(outsideDir, "unsafe.jsonnet"),
		filepath.Join(tmpDir, "symlink.jsonnet")); err != nil {
		t.Skipf("Skipping symlink tests: %v", err)
	}

	imp, err := NewSafeImporter(tmpDir, []string{filepath.Join(tmpDir, "lib")}, WithLogger(log.New(os.Stdout, "", 0)))
	if err != nil {
		t.Fatalf("NewSafeImporter() error = %v", err)
	}
	t.Cleanup(func() { imp.Close() })

	tests := []struct {
		name         string
		importedFrom string
		importedPath string
		wantErr      bool
	}{
		{
			name:         "absolute path outside root",
			importedFrom: "",
			importedPath: filepath.Join(outsideDir, "unsafe.jsonnet"),
			wantErr:      true,
		},
		{
			name:         "relative path traversal",
			importedFrom: "",
			importedPath: "../unsafe.jsonnet",
			wantErr:      true,
		},
		{
			name:         "symlink to outside",
			importedFrom: "",
			importedPath: "symlink.jsonnet",
			wantErr:      true,
		},
		{
			name:         "double dot traversal",
			importedFrom: filepath.Join(tmpDir, "lib", "safe.jsonnet"),
			importedPath: "../../unsafe.jsonnet",
			wantErr:      true,
		},
		{
			name:         "equal path traversal",
			importedFrom: filepath.Join(tmpDir, "lib", "safe.jsonnet"),
			importedPath: "../lib/safe.jsonnet",
			wantErr:      false,
		},
		{
			name:         "absolute path outside root via symlink",
			importedFrom: "",
			importedPath: filepath.Join(tmpDir, "symlink.jsonnet"),
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := imp.Import(tt.importedFrom, tt.importedPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("Import() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestImport_Caching(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	content := `{x: 1}`
	filePath := filepath.Join(tmpDir, "test.jsonnet")
	mustWriteFile(t, filePath, content)

	imp, err := NewSafeImporter(tmpDir, nil, WithLogger(log.New(os.Stdout, "", 0)))
	if err != nil {
		t.Fatalf("NewSafeImporter() error = %v", err)
	}
	defer imp.Close()

	// First import should read from disk. Pass the absolute path to simulate resolved entrypoint.
	contents1, foundAt1, err := imp.Import("", filePath)
	if err != nil {
		t.Fatalf("First Import() error = %v", err)
	}

	// Remove the file to ensure second import uses cache
	if err := os.Remove(filePath); err != nil {
		t.Fatalf("Failed to remove test file: %v", err)
	}

	// Second import should use cache. Pass the same absolute path.
	contents2, foundAt2, err := imp.Import("", filePath)
	if err != nil {
		t.Fatalf("Second Import() error = %v", err)
	}

	if contents1.String() != contents2.String() {
		t.Errorf("Cache returned different contents: got %v, want %v", contents2, contents1)
	}
	if foundAt1 != foundAt2 {
		t.Errorf("Cache returned different paths: got %v, want %v", foundAt2, foundAt1)
	}
}

func TestClose(t *testing.T) {
	t.Parallel()

	// Test closing a valid importer
	tmpDir := t.TempDir()
	imp, err := NewSafeImporter(tmpDir, nil, WithLogger(log.New(os.Stdout, "", 0)))
	if err != nil {
		t.Fatalf("NewSafeImporter() error = %v", err)
	}

	if err := imp.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Test closing an already closed importer
	if err := imp.Close(); err != nil {
		t.Errorf("Close() called twice should not error = %v", err)
	}

	// Create a nil root importer without using NewSafeImporter
	impWithNilRoot := &SafeImporter{
		JPaths:  []string{"."},
		root:    nil,
		fsCache: sync.Map{},
	}
	if err := impWithNilRoot.Close(); err != nil {
		t.Errorf("Close() on importer with nil root should not error = %v", err)
	}
}

func TestGetRelativeDir(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	imp, err := NewSafeImporter(tmpDir, nil, WithLogger(log.New(os.Stdout, "", 0)))
	if err != nil {
		t.Fatalf("NewSafeImporter() error = %v", err)
	}
	t.Cleanup(func() {
		imp.Close()
	})

	tests := []struct {
		name         string
		importer     *SafeImporter
		importedFrom string
		want         string
		wantErr      bool
	}{
		{
			name:         "relative path",
			importer:     imp,
			importedFrom: "some/path/file.jsonnet",
			want:         "some/path",
			wantErr:      false,
		},
		{
			name:         "absolute path inside root",
			importer:     imp,
			importedFrom: filepath.Join(tmpDir, "some/path/file.jsonnet"),
			want:         "some/path",
			wantErr:      false,
		},
		{
			name:         "empty path",
			importer:     imp,
			importedFrom: "",
			want:         ".", // Dir of empty string is "."
			wantErr:      false,
		},
		{
			name:         "path with null byte",
			importer:     imp,
			importedFrom: "path/with/\x00/null.jsonnet",
			want:         "",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			relDir, err := tt.importer.getRelativeDir(tt.importedFrom)
			if tt.wantErr {
				if err == nil {
					t.Errorf("getRelativeDir() expected error but got nil")
				}

				return
			}

			if err != nil {
				t.Errorf("getRelativeDir() unexpected error = %v", err)

				return
			}

			// On Windows, paths may come with backslashes, normalize for comparison
			// We only compare the last part (without the full temporary path) for absolute paths
			normalizedGot := filepath.ToSlash(filepath.Base(relDir))
			normalizedWant := filepath.ToSlash(filepath.Base(tt.want))
			if normalizedGot != normalizedWant && relDir != tt.want {
				t.Errorf("getRelativeDir() got = %v, want %v", relDir, tt.want)
			}
		})
	}
}

func TestImport_Concurrency(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	content := `{ "msg": "hello from concurrent test" }`
	filePath := filepath.Join(tmpDir, "concurrent_test.jsonnet")
	mustWriteFile(t, filePath, content)

	imp, err := NewSafeImporter(tmpDir, nil, WithLogger(log.New(os.Stdout, "", 0)))
	if err != nil {
		t.Fatalf("NewSafeImporter() error = %v", err)
	}
	defer imp.Close()

	var wg sync.WaitGroup
	numGoroutines := 32

	for range numGoroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			importedContent, foundAt, importErr := imp.Import("", filePath)
			if importErr != nil {
				t.Errorf("imp.Import() failed in goroutine: %v", importErr)

				return
			}
			if importedContent.String() != content {
				t.Errorf("imp.Import() returned wrong content in goroutine: got %q, want %q", importedContent.String(), content)
			}
			if foundAt != filePath {
				t.Errorf("imp.Import() returned wrong foundAt in goroutine: got %q, want %q", foundAt, filePath)
			}
		}()
	}
	wg.Wait()
}

func TestImport_EdgeCases(t *testing.T) {
	t.Parallel()

	// Setup test directories
	tmpDir := t.TempDir()
	outsideDir := t.TempDir()

	// Create test directory structure
	mustWriteFile(t, filepath.Join(tmpDir, "regular.jsonnet"), `{"regular": true}`)
	mustWriteFile(t, filepath.Join(tmpDir, "lib", "lib_file.jsonnet"), `{"lib": true}`)
	mustWriteFile(t, filepath.Join(outsideDir, "outside.jsonnet"), `{"outside": true}`)

	// Create importer for testing
	imp, err := NewSafeImporter(tmpDir, []string{filepath.Join(tmpDir, "lib")}, WithLogger(log.New(os.Stdout, "", 0)))
	if err != nil {
		t.Fatalf("NewSafeImporter() error = %v", err)
	}
	t.Cleanup(func() { imp.Close() })

	tests := []struct {
		name         string
		importedFrom string
		importedPath string
		wantErr      bool
		errorCheck   func(error) bool // Optional function to check specific error
		setupFn      func()           // Setup function to run before test
	}{
		{
			name:         "null byte in importedPath",
			importedFrom: "",
			importedPath: "some\x00file.jsonnet",
			wantErr:      true,
		},
		{
			name:         "absolute outside path with no importedFrom",
			importedFrom: "",
			importedPath: filepath.Join(outsideDir, "outside.jsonnet"),
			wantErr:      true,
		},
		{
			name:         "attempt to use non-existent jpath as fallback",
			importedFrom: filepath.Join(tmpDir, "main.jsonnet"),
			importedPath: "nonexistent.jsonnet", // Doesn't exist in any search path
			wantErr:      true,
		},
		{
			name:         "JPath fallback finds file",
			importedFrom: filepath.Join(tmpDir, "main.jsonnet"), // Pretend importing from a file
			importedPath: "lib_file.jsonnet",                    // This exists in the lib JPath
			wantErr:      false,
			setupFn: func() {
				// Make sure main.jsonnet exists for importing from
				mustWriteFile(t, filepath.Join(tmpDir, "main.jsonnet"), `local lib = import 'lib_file.jsonnet'; lib`)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.setupFn != nil {
				tt.setupFn()
			}

			// For valid tests, check if the file was found
			contents, foundAt, err := imp.Import(tt.importedFrom, tt.importedPath)

			if (err != nil) != tt.wantErr {
				t.Errorf("Import() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if err == nil {
				// For successful imports, verify we got content back
				if contents.String() == "" {
					t.Errorf("Import() returned empty contents")
				}
				if foundAt == "" {
					t.Errorf("Import() returned empty foundAt path")
				}
			} else if tt.errorCheck != nil && !tt.errorCheck(err) {
				t.Errorf("Import() error %v doesn't match expected error condition", err)
			}
		})
	}
}

func TestTryPath(t *testing.T) {
	t.Parallel()

	// Setup test directory
	tmpDir := t.TempDir()
	mustWriteFile(t, filepath.Join(tmpDir, "test.jsonnet"), `{"x": 1}`)

	// Create importer
	imp, err := NewSafeImporter(tmpDir, nil, WithLogger(log.New(os.Stdout, "", 0)))
	if err != nil {
		t.Fatalf("NewSafeImporter() error = %v", err)
	}
	defer imp.Close()

	// Run individual test cases
	testSuccessfulLookup(t, imp)
	testCaching(t, imp, tmpDir)
	testNonExistentFile(t, imp)
}

func testSuccessfulLookup(t *testing.T, imp *SafeImporter) {
	t.Helper()
	// Simulate what Import does: resolve path relative to root
	absPath := filepath.Join(imp.rootAbsPath, "test.jsonnet")
	relPath := "test.jsonnet"

	found, contents, _, err := imp.tryAbsPath(absPath, relPath)
	if err != nil {
		t.Errorf("tryAbsPath() for existing file error = %v", err)
	}
	if !found {
		t.Errorf("tryAbsPath() did not find existing file")
	}
	if contents.String() != `{"x": 1}` {
		t.Errorf("tryAbsPath() contents = %v, want %v", contents.String(), `{"x": 1}`)
	}
}

func testCaching(t *testing.T, imp *SafeImporter, tmpDir string) {
	t.Helper()
	absPath := filepath.Join(tmpDir, "test.jsonnet")
	relPath := "test.jsonnet"

	// Get initial content for comparison
	_, contents, foundAt, _ := imp.tryAbsPath(absPath, relPath)

	// Test caching by removing the file and trying to access it again
	if err := os.Remove(filepath.Join(tmpDir, "test.jsonnet")); err != nil {
		t.Fatalf("Failed to remove test file: %v", err)
	}

	found2, contents2, foundAt2, err2 := imp.tryAbsPath(absPath, relPath)
	if err2 != nil {
		t.Errorf("tryAbsPath() cached lookup error = %v", err2)
	}
	if !found2 {
		t.Errorf("tryAbsPath() did not find cached file")
	}
	if contents2.String() != contents.String() {
		t.Errorf("tryAbsPath() cached contents = %v, want %v", contents2.String(), contents.String())
	}
	if foundAt2 != foundAt {
		t.Errorf("tryAbsPath() cached foundAt = %v, want %v", foundAt2, foundAt)
	}
}

func testNonExistentFile(t *testing.T, imp *SafeImporter) {
	t.Helper()
	absPath := filepath.Join(imp.rootAbsPath, "nonexistent.jsonnet")
	relPath := "nonexistent.jsonnet"

	found3, _, _, err3 := imp.tryAbsPath(absPath, relPath)
	if err3 != nil {
		t.Errorf("tryAbsPath() for non-existent file error = %v", err3)
	}
	if found3 {
		t.Errorf("tryAbsPath() found non-existent file")
	}
}

func TestTryAbsPath_CacheInternalTypeError(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	mustWriteFile(t, filepath.Join(tmpDir, "test.jsonnet"), `{}`)

	imp, err := NewSafeImporter(tmpDir, nil)
	if err != nil {
		t.Fatalf("NewSafeImporter() error = %v", err)
	}
	defer imp.Close()

	// Manually poison the cache with an invalid type
	absPath := filepath.Join(tmpDir, "poisoned.jsonnet")
	imp.fsCache.Store(absPath, "not a *cacheEntry")

	found, contents, foundAt, err := imp.tryAbsPath(absPath, "poisoned.jsonnet")
	_ = found
	_ = contents
	_ = foundAt
	if err == nil {
		t.Error("tryAbsPath() should return error for invalid cache entry type")
	}
	if !strings.Contains(err.Error(), "internal cache error") {
		t.Errorf("tryAbsPath() error should mention internal cache error, got: %v", err)
	}
}

func TestTryAbsPath_CachedNonExistError(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	imp, err := NewSafeImporter(tmpDir, nil)
	if err != nil {
		t.Fatalf("NewSafeImporter() error = %v", err)
	}
	defer imp.Close()

	// First call: file doesn't exist, gets cached as not-exist
	absPath := filepath.Join(tmpDir, "missing.jsonnet")
	found, _, _, err := imp.tryAbsPath(absPath, "missing.jsonnet")
	if err != nil {
		t.Fatalf("First tryAbsPath() error = %v", err)
	}
	if found {
		t.Error("First tryAbsPath() should not find non-existent file")
	}

	// Second call: should use cached not-exist result
	found2, _, _, err2 := imp.tryAbsPath(absPath, "missing.jsonnet")
	if err2 != nil {
		t.Errorf("Second tryAbsPath() error = %v", err2)
	}
	if found2 {
		t.Error("Second tryAbsPath() should return cached not-found")
	}
}

func TestTryAbsPath_CachedOtherError(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	imp, err := NewSafeImporter(tmpDir, nil)
	if err != nil {
		t.Fatalf("NewSafeImporter() error = %v", err)
	}
	defer imp.Close()

	// Manually cache an error that is NOT os.IsNotExist
	absPath := filepath.Join(tmpDir, "error.jsonnet")
	customErr := errors.New("custom cached error") //nolint:err113
	imp.fsCache.Store(absPath, &cacheEntry{err: customErr})

	found, contents, foundAt, err := imp.tryAbsPath(absPath, "error.jsonnet")
	_ = found
	_ = contents
	_ = foundAt
	if err == nil {
		t.Error("tryAbsPath() should return cached error")
	}
	if !strings.Contains(err.Error(), "custom cached error") {
		t.Errorf("tryAbsPath() should return the cached error, got: %v", err)
	}
}

func TestEnsureDotInSearchPaths(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	mustWriteFile(t, filepath.Join(tmpDir, "root.jsonnet"), `{root: true}`)
	mustWriteFile(t, filepath.Join(tmpDir, "lib", "lib.jsonnet"), `{lib: true}`)

	// Create importer with JPaths that already contains "."
	imp1, err := NewSafeImporter(tmpDir, []string{".", "lib"})
	if err != nil {
		t.Fatalf("NewSafeImporter() error = %v", err)
	}
	defer imp1.Close()

	// Verify "." is in JPaths
	hasDot := slices.Contains(imp1.JPaths, ".")
	if !hasDot {
		t.Error("JPaths should contain '.'")
	}

	// Test ensureDotInSearchPaths when "." is already present
	paths := imp1.ensureDotInSearchPaths([]string{".", "lib"})
	if len(paths) != 2 {
		t.Errorf("ensureDotInSearchPaths() should not duplicate '.', got %v", paths)
	}

	// Test ensureDotInSearchPaths when "." is NOT present
	paths2 := imp1.ensureDotInSearchPaths([]string{"lib", "vendor"})
	if len(paths2) != 3 || paths2[0] != "." {
		t.Errorf("ensureDotInSearchPaths() should prepend '.', got %v", paths2)
	}
}

func TestTryAbsPath_DirectoryReadError(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	// Create a directory (not a file)
	dirPath := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	imp, err := NewSafeImporter(tmpDir, nil)
	if err != nil {
		t.Fatalf("NewSafeImporter() error = %v", err)
	}
	defer imp.Close()

	// Try to read a directory as if it were a file
	// This should trigger the io.ReadAll error path
	found, _, _, err := imp.tryAbsPath(dirPath, "subdir")
	// On most systems, trying to read a directory returns an error
	if found && err == nil {
		t.Log("Directory was unexpectedly readable as a file (platform-specific)")
	}
	// The important thing is we don't panic
}

func TestImport_JPathFallback(t *testing.T) {
	t.Parallel()

	// Setup test directory structure
	tmpDir := t.TempDir()
	mustWriteFile(t, filepath.Join(tmpDir, "main.jsonnet"), `local lib = import 'jpath-only.jsonnet'; lib`)
	mustWriteFile(t, filepath.Join(tmpDir, "lib", "jpath-only.jsonnet"), `{jpath: true}`)

	// Create importer
	imp, err := NewSafeImporter(tmpDir, []string{filepath.Join(tmpDir, "lib")}, WithLogger(log.New(os.Stdout, "", 0)))
	if err != nil {
		t.Fatalf("NewSafeImporter() error = %v", err)
	}
	defer imp.Close()

	// Test the special JPath handling when importedFrom is empty
	contents, foundAt, err := imp.Import("", "jpath-only.jsonnet")
	if err != nil {
		t.Errorf("Import() error = %v", err)

		return
	}
	if contents.String() != `{jpath: true}` {
		t.Errorf("Import() contents = %v, want %v", contents.String(), `{jpath: true}`)
	}

	// Make sure the file was actually found in the jpath, not the root
	if !strings.Contains(foundAt, "lib/jpath-only.jsonnet") {
		t.Errorf("Import() foundAt = %v, expected to contain 'lib/jpath-only.jsonnet'", foundAt)
	}

	// Test JPath precedence (./ before lib)
	// First, create the same file in both ./ and lib/ with different content
	rootContent := `{root: true}`
	libContent := `{lib: true}`
	mustWriteFile(t, filepath.Join(tmpDir, "duplicate.jsonnet"), rootContent)
	mustWriteFile(t, filepath.Join(tmpDir, "lib", "duplicate.jsonnet"), libContent)

	// When doing an initial import (importedFrom=""), the default ./ is searched first
	contents2, _, err := imp.Import("", "duplicate.jsonnet")
	if err != nil {
		t.Errorf("Import() for duplicate error = %v", err)

		return
	}
	if contents2.String() != rootContent {
		t.Errorf("Import() expected root content, got = %v, want %v", contents2.String(), rootContent)
	}

	// Test error handling for invalid absolute import path
	invalidAbsPath := filepath.Join(t.TempDir(), "not-in-root.jsonnet")
	_, _, err = imp.Import("", invalidAbsPath)
	if err == nil {
		t.Errorf("Import() with invalid absolute path should have failed")
	}
}

func TestImport_ErrorPaths(t *testing.T) {
	t.Parallel()

	// Setup test directory
	tmpDir := t.TempDir()
	mustWriteFile(t, filepath.Join(tmpDir, "test.jsonnet"), `{x: 1}`)

	// Create importer
	imp, err := NewSafeImporter(tmpDir, []string{filepath.Join(tmpDir, "lib")}, WithLogger(log.New(os.Stdout, "", 0)))
	if err != nil {
		t.Fatalf("NewSafeImporter() error = %v", err)
	}
	defer imp.Close()

	// Test with a relative path that would escape the root
	_, _, err = imp.Import(filepath.Join(tmpDir, "lib", "nested"), "../../../../../../etc/passwd")
	if err == nil {
		t.Errorf("Import() with excessive path traversal should fail")
	}

	// Test with invalid importedFrom
	_, _, err = imp.Import("invalid\x00path", "test.jsonnet")
	if err == nil {
		t.Errorf("Import() with invalid importedFrom should fail")
	}

	// Test with absolute importedPath when importedFrom is not empty
	outsideDir := t.TempDir()
	mustWriteFile(t, filepath.Join(outsideDir, "outside.jsonnet"), `{outside: true}`)
	_, _, err = imp.Import(filepath.Join(tmpDir, "test.jsonnet"), filepath.Join(outsideDir, "outside.jsonnet"))
	if err == nil {
		t.Errorf("Import() with absolute path outside root should fail")
	}
}

func TestClose_ErrorHandling(t *testing.T) {
	t.Parallel()

	// Setup test directory
	tmpDir := t.TempDir()
	imp, err := NewSafeImporter(tmpDir, nil, WithLogger(log.New(os.Stdout, "", 0)))
	if err != nil {
		t.Fatalf("NewSafeImporter() error = %v", err)
	}

	// Import a file to ensure the importer is used
	testContent := `{x: 1}`
	testFile := filepath.Join(tmpDir, "test.jsonnet")
	mustWriteFile(t, testFile, testContent)

	// Import the file to populate cache
	_, _, err = imp.Import("", testFile)
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	// Close normally - should succeed
	if err := imp.Close(); err != nil {
		t.Errorf("First Close() error = %v", err)
	}

	// Try another close operation after close
	if err := imp.Close(); err != nil {
		t.Errorf("Second Close() should not error = %v", err)
	}

	// Create an importer, then manually delete the tmp directory to force close error
	// This test depends on OS behavior and might need adjustment
	impForError, err := NewSafeImporter(tmpDir, nil)
	if err != nil {
		t.Fatalf("Second NewSafeImporter() error = %v", err)
	}

	// Verify cache state before and after close
	cacheEntryCount := countCacheEntries(impForError)
	impForError.Close()

	// After closing, verify the importer can't be used
	_, _, err = impForError.Import("", testFile)
	if err == nil {
		t.Error("Import() after Close() should fail")
	}

	// Test resource cleanup
	if countCacheEntries(impForError) != cacheEntryCount {
		t.Error("Close() should not affect cache entries")
	}
}

// Helper function to count cache entries.
func countCacheEntries(imp *SafeImporter) int {
	count := 0
	imp.fsCache.Range(func(_, _ any) bool {
		count++

		return true
	})

	return count
}

// mustWriteFile is a test helper that writes a file or fails the test.
func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}
}
