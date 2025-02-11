// Package main demonstrates the usage of safesonnet importer
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/google/go-jsonnet"
	"github.com/thevilledev/safesonnet"
)

const jsonnetCode = `
local config = import 'config.jsonnet';
local utils = import 'utils.jsonnet'; // relative import to jpath
{
	name: config.name,
	greeting: utils.makeGreeting(config.name)
}
`

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// Create a new SafeImporter with root directory and library paths
	rootDir := "jsonnet"
	importer, err := safesonnet.NewSafeImporter(rootDir, []string{
		filepath.Join(rootDir, "lib"), // Library path relative to workspace
	})
	if err != nil {
		return fmt.Errorf("failed to create importer: %w", err)
	}
	defer importer.Close()

	// Create a new Jsonnet VM and configure it
	vm := jsonnet.MakeVM()
	vm.Importer(importer)

	// Evaluate the Jsonnet code
	result, err := vm.EvaluateAnonymousSnippet("example.jsonnet", jsonnetCode)
	if err != nil {
		return fmt.Errorf("failed to evaluate jsonnet: %w", err)
	}

	fmt.Fprintln(os.Stdout, result)
	return nil
}
