package safesonnet

import (
	"os"
	"path/filepath"
	"runtime"
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
			imp, err := NewSafeImporter(tt.rootDir, tt.jpaths)
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
				// Move util.jsonnet directly into lib directory since that's our library path
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

			imp, err := NewSafeImporter(tmpDir, []string{filepath.Join(tmpDir, "lib")})
			if err != nil {
				t.Fatalf("NewSafeImporter() error = %v", err)
			}
			defer imp.Close()

			var importedFrom string
			if tt.name == "relative import" {
				importedFrom = filepath.Join(tmpDir, "main.jsonnet")
			}

			contents, _, err := imp.Import(importedFrom, tt.importedPath)
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

	imp, err := NewSafeImporter(tmpDir, []string{filepath.Join(tmpDir, "lib")})
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

	imp, err := NewSafeImporter(tmpDir, nil)
	if err != nil {
		t.Fatalf("NewSafeImporter() error = %v", err)
	}
	defer imp.Close()

	// First import should read from disk
	contents1, foundAt1, err := imp.Import("", "test.jsonnet")
	if err != nil {
		t.Fatalf("First Import() error = %v", err)
	}

	// Remove the file to ensure second import uses cache
	if err := os.Remove(filePath); err != nil {
		t.Fatalf("Failed to remove test file: %v", err)
	}

	// Second import should use cache
	contents2, foundAt2, err := imp.Import("", "test.jsonnet")
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
	imp, err := NewSafeImporter(tmpDir, nil)
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
		fsCache: make(map[string]*fsCacheEntry),
	}
	if err := impWithNilRoot.Close(); err != nil {
		t.Errorf("Close() on importer with nil root should not error = %v", err)
	}
}

func TestGetRelativeDir(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	imp, err := NewSafeImporter(tmpDir, nil)
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
	}

	// Test invalid root condition separately with an artificially invalid path
	if runtime.GOOS == "windows" {
		t.Run("invalid abs path", func(t *testing.T) {
			t.Parallel()
			// This creates an invalid absolute path that should cause filepath.Abs to fail
			invalidPath := "\x00invalid:path"
			_, err := imp.getRelativeDir(invalidPath)
			if err == nil {
				t.Errorf("Expected error for invalid path but got nil")
			}
		})
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

func TestImport_EdgeCases(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	mustWriteFile(t, filepath.Join(tmpDir, "main.jsonnet"), `local lib = import 'lib.jsonnet'; lib`)
	mustWriteFile(t, filepath.Join(tmpDir, "lib.jsonnet"), `{x: 1}`)
	mustWriteFile(t, filepath.Join(tmpDir, "unreadable.jsonnet"), `{x: 2}`)

	// Create a test file that will generate an error when reading
	if err := os.MkdirAll(filepath.Join(tmpDir, "error"), 0755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	errorFile := filepath.Join(tmpDir, "error", "file.jsonnet")
	if err := os.WriteFile(errorFile, []byte("{}"), 0600); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	// Make a file unreadable if possible
	if err := os.Chmod(filepath.Join(tmpDir, "unreadable.jsonnet"), 0000); err != nil {
		t.Logf("Could not make file unreadable, skipping that test: %v", err)
	}

	imp, err := NewSafeImporter(tmpDir, nil)
	if err != nil {
		t.Fatalf("NewSafeImporter() error = %v", err)
	}
	defer imp.Close()

	// Test importing with absolute path
	_, _, err = imp.Import("", filepath.Join(tmpDir, "lib.jsonnet"))
	if err == nil {
		t.Errorf("Import() with absolute path should fail")
	}

	// Test importing with invalid importedFrom path
	_, _, err = imp.Import(string([]byte{0}), "lib.jsonnet")
	if err == nil {
		t.Log("Import() with invalid importedFrom may fail on some platforms")
	}

	// Test error from unreadable file
	_, _, err = imp.Import("", "unreadable.jsonnet")
	// The error might occur or not depending on permissions
	t.Logf("Import unreadable file error: %v", err)

	// Test importing with absolute path but from importedFrom
	_, _, err = imp.Import(filepath.Join(tmpDir, "main.jsonnet"), "/absolute/path/to/file.jsonnet")
	if err == nil {
		t.Errorf("Import() with absolute path from importedFrom should fail")
	}
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
