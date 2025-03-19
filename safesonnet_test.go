package safesonnet

import (
	"os"
	"path/filepath"
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
