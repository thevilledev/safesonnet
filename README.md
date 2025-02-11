# SafeSonnet

SafeSonnet is a secure file importer for [google/go-jsonnet](https://github.com/google/go-jsonnet) that restricts file imports to a specific directory using [Go 1.24's new `os.Root` functionality](https://tip.golang.org/doc/go1.24#directory-limited-filesystem-access). This helps prevent path traversal attacks and ensures that Jsonnet imports can only access files within a designated directory.

## Installation

```bash
go get github.com/thevilledev/safesonnet
```

Requires Go 1.24.

## Usage

See [example](example/) directory for a complete working example.

Basic usage:

```go
importer, err := safesonnet.NewSafeImporter("jsonnet", []string{
    filepath.Join("jsonnet", "lib"), // Library path relative to workspace
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

- No access to files outside the specified root directory
- No following of symbolic links that point outside the root
- No absolute path traversal
- No relative path traversal (e.g., using `../`)
- Library paths (JPaths) must be within the root directory

## License

MIT License - see [LICENSE](LICENSE) file for full details.
