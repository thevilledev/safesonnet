package safesonnet_test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/thevilledev/safesonnet"
)

func Example() {
	// Create a temporary directory for our examples
	rootDir, err := os.MkdirTemp("", "safesonnet-example")
	if err != nil {
		fmt.Printf("Failed to create temp dir: %v\n", err)

		return
	}
	defer os.RemoveAll(rootDir)

	// Create some jsonnet files
	if err := os.MkdirAll(filepath.Join(rootDir, "lib"), 0755); err != nil {
		fmt.Printf("Failed to create lib dir: %v\n", err)

		return
	}

	mainJsonnet := `local utils = import 'lib/utils.jsonnet';
{
  result: utils.add(40, 2)
}`

	utilsJsonnet := `{
  add(a, b): a + b,
}`

	if err := os.WriteFile(filepath.Join(rootDir, "main.jsonnet"), []byte(mainJsonnet), 0o600); err != nil {
		fmt.Printf("Failed to write main.jsonnet: %v\n", err)

		return
	}

	if err := os.WriteFile(filepath.Join(rootDir, "lib", "utils.jsonnet"), []byte(utilsJsonnet), 0o600); err != nil {
		fmt.Printf("Failed to write utils.jsonnet: %v\n", err)

		return
	}

	// Create a SafeImporter with the root directory and a library path
	importer, err := safesonnet.NewSafeImporter(rootDir, []string{filepath.Join(rootDir, "lib")})
	if err != nil {
		fmt.Printf("Failed to create importer: %v\n", err)

		return
	}
	defer importer.Close()

	// Import a file
	contents, foundAt, err := importer.Import("", "main.jsonnet")
	if err != nil {
		fmt.Printf("Failed to import: %v\n", err)

		return
	}

	fmt.Printf("Found file at: %s\n", filepath.Base(foundAt))
	fmt.Printf("Contents: %s\n", contents.String())

	// Output:
	// Found file at: main.jsonnet
	// Contents: local utils = import 'lib/utils.jsonnet';
	// {
	//   result: utils.add(40, 2)
	// }
}
