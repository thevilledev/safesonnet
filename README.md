# SafeSonnet

[![Go Reference](https://pkg.go.dev/badge/github.com/thevilledev/safesonnet.svg)](https://pkg.go.dev/github.com/thevilledev/safesonnet)
[![test](https://github.com/thevilledev/go-thespine/actions/workflows/ci.yaml/badge.svg)](https://github.com/thevilledev/safesonnet/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/thevilledev/safesonnet)](https://goreportcard.com/report/github.com/thevilledev/safesonnet)

SafeSonnet is a secure file importer for [google/go-jsonnet](https://github.com/google/go-jsonnet) that restricts file imports to a specific directory using `os.Root` functionality [introduced in Go 1.24](https://tip.golang.org/doc/go1.24#directory-limited-filesystem-access). This helps prevent path traversal attacks and ensures that Jsonnet imports can only access files within a designated directory.

See [docs/spec.md](docs/spec.md) for the full specification, with differences to the built-in go-jsonnet file importer.

## Installation

```bash
go get github.com/thevilledev/safesonnet
```

Requires Go 1.24.

## Usage

See [example](example/) directory for a complete working example.

Basic usage:

```go
rootDir := "jsonnet"
impporter, err := safesonnet.NewSafeImporter(rootDir, []string{
	"lib", // Library path relative to rootDir
})
if err != nil {
    log.Fatal(err)
}
// Close is required to release the os.Root file descriptor
defer importer.Close()

vm := jsonnet.MakeVM()
vm.Importer(importer)
```

Note: Unlike `jsonnet.FileImporter`, `SafeImporter` requires calling `Close()` to release the underlying `os.Root` file descriptor. Always use `defer importer.Close()` after creating the importer.

## Security

SafeSonnet uses Go 1.24's `os.Root` functionality to ensure that file access is restricted to the specified directory tree. This means:

- No access to files outside the specified root directory.
- No following of symbolic links that point outside the root.
- No absolute path traversal.
- No relative path traversal (e.g., using `../`).
- Library paths (JPaths) must be within the root directory.

## License

MIT License - see [LICENSE](LICENSE) file for full details.
