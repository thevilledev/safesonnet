# SafeSonnet Importer Spec

## Introduction

SafeSonnet provides a `SafeImporter` designed as a secure alternative to the standard `FileImporter` in `google/go-jsonnet`. Its primary goal is to prevent path traversal attacks and restrict all Jsonnet file import operations to a designated root directory and its subdirectories. This is crucial for applications that evaluate Jsonnet code from potentially untrusted sources or require strict control over file system access.

## How SafeSonnet's `SafeImporter` Works

The `SafeImporter` provides a secure way to import Jsonnet files by confining all file system operations to a designated root directory. Its architecture revolves around Go's `os.Root` mechanism and a structured import resolution process.

### 1. Core Security Foundation: Filesystem Sandboxing with `os.Root`

At its heart, `SafeImporter` uses `os.OpenRoot(rootDir)` to obtain a special file descriptor. This descriptor represents a sandboxed view of the filesystem, strictly limited to the `rootDir` and its subdirectories. All file read operations performed by the importer occur through this sandboxed view.

Key characteristics of this sandboxing:
-   **Boundary Enforcement**: Access to any file or directory outside the specified `rootDir` is prevented at the operating system level.
-   **Traversal Prevention**: Attempts to navigate outside the `rootDir` (e.g., using `../` or absolute paths pointing elsewhere) are blocked.
-   **Symbolic Link Restriction**: Symbolic links that resolve to a path outside the `rootDir` cannot be followed.
-   **Resource Management**: This `os.Root` file descriptor is a system resource. The `SafeImporter` requires its `Close()` method to be called (usually with `defer importer.Close()`) to release this resource when the importer is no longer needed.

### 2. Initialization and Configuration with `NewSafeImporter`

When a `SafeImporter` is created, the security context is established:
-   **`rootDir`**: Defines the single directory that serves as the secure boundary for all import operations. Must not be empty.
-   **JPaths (Library Paths)**: A list of search paths for Jsonnet libraries. Crucially, `SafeImporter` verifies that *all* provided JPaths are located *within* the `rootDir`. If any JPath points outside, initialization fails. If no JPaths are given, the `rootDir` itself (`.`) is the default search location.
-   **Absolute Root Path**: The importer resolves and stores the absolute path to `rootDir` for internal validation logic.
-   **Optional Logger**: A logger can be provided via `WithLogger()` option for debugging import operations.

### 3. Import Resolution Strategy for the `Import` method

When `go-jsonnet` requests a file, the `SafeImporter` follows a prioritized search strategy, always respecting the `rootDir` boundary:

**A. Input Validation**
   - Before any path resolution, both `importedFrom` and `importedPath` are checked for null bytes (`\x00`). Paths containing null bytes are rejected with `ErrInvalidNullByte`.

**B. Initial File Load (e.g., `vm.EvaluateFile(entrypoint.jsonnet)`)**
   1.  **Path Scrutiny**: The initial `importedPath` (which might be relative to the current working directory or absolute) is fully resolved.
   2.  **Root Confinement Check**:
       -   If the resolved path is *inside* the `rootDir`, the importer attempts to load it directly from this location (relative to the `rootDir`).
       -   If the resolved path is *outside* the `rootDir`:
           -   If the *original* `importedPath` was absolute, an error is immediately returned (`ErrForbiddenAbsolutePath`).
           -   If the *original* `importedPath` was relative, this means the current working directory isn't aligned with the `rootDir` for this path. The importer then proceeds to search for the file using JPaths.
   3.  **JPath Fallback**: If the file isn't found directly within the root (and was eligible for JPath search), the JPath search mechanism (see below) is invoked.

**C. Subsequent Imports (e.g., `import "lib/helper.libsonnet"` from within another Jsonnet file)**
   1.  **Relative to Current File**: If `importedPath` is relative, the importer first tries to find it in the same directory as `importedFrom` (the file doing the importing). This search is, of course, confined within the `rootDir`.
   2.  **Absolute Path Handling**: If `importedPath` is absolute, the importer checks if this path is within the `rootDir`.
       -   If yes, it attempts to load it.
       -   If no, an error is returned (`ErrForbiddenAbsolutePath`).
   3.  **Traversal Detection**: If a relative import would escape the `rootDir` (e.g., excessive `../`), `ErrForbiddenRelativePathTraversal` is returned.
   4.  **JPath Fallback**: If the file is not found via the above relative or permissible absolute path lookups, the JPath search mechanism is invoked.

**D. JPath Search Mechanism**
   - The importer iterates through the configured JPaths (which are all guaranteed to be within `rootDir`).
   - For initial file loads that fall back to JPath search, the `rootDir` itself (`.`) is implicitly added as a search path if not already present.
   - It attempts to load `importedPath` relative to each JPath.
   - The first successful find is returned.

**E. Security Checks During Resolution:**
   - Throughout the process, `tryAbsPath` (an internal helper) uses `os.Root` for actual file operations.
   - It explicitly checks for and prevents path traversals (`../`) that would escape the `rootDir`.
   - It ensures absolute import paths do not point outside the `rootDir`.

### 4. Caching with `fsCache`

To optimize performance, `SafeImporter` caches the results of file lookups:
-   It uses a `sync.Map` to store both successfully read file contents (`jsonnet.Contents`) and "file not found" statuses.
-   Cache keys are the absolute filesystem paths, ensuring consistent lookups across different import contexts.
-   The cache is thread-safe and supports concurrent access during parallel Jsonnet evaluation.

### 5. Clear Error Reporting

`SafeImporter` uses a set of specific error types to provide clear diagnostics when an import is denied due to security constraints or configuration issues:

| Error | Description |
| :---- | :---------- |
| `ErrEmptyRootDir` | Root directory parameter was empty |
| `ErrOpenRootDir` | Failed to open the root directory with `os.OpenRoot` |
| `ErrAbsPath` | Failed to resolve the absolute path of root |
| `ErrJPathOutsideRoot` | A JPath is located outside the root directory |
| `ErrForbiddenAbsolutePath` | An absolute import path points outside the root |
| `ErrForbiddenRelativePathTraversal` | A relative import would traverse outside the root |
| `ErrInvalidNullByte` | A path contains a null byte character |
| `ErrFileNotFound` | File was not found in any search path |
| `ErrReadFile` | Failed to read the file contents |
| `ErrCacheInternalType` | Internal cache corruption (unexpected type) |

## Differences from `go-jsonnet.FileImporter`

| Feature                  | `safesonnet.SafeImporter`                                    | `go-jsonnet.FileImporter`                                |
| :----------------------- | :----------------------------------------------------------- | :------------------------------------------------------- |
| **Security Model**       | Strong sandboxing via `os.Root`. All access confined to a `rootDir`. | Standard OS file operations. Relies on correct path handling by user; vulnerable to traversal if paths are not sanitized. |
| **Root Directory**       | Explicit `rootDir` at initialization. All paths relative to this. | No inherent "root" concept. JPaths are system-wide.     |
| **JPath Validation**     | JPaths *must* be within `rootDir`. Validated at init.        | JPaths can be any directory on the filesystem. No validation against a root. |
| **`Close()` Method**     | **Required**. `defer importer.Close()` to release `os.Root` resources. | Not present. No special resources to release.             |
| **Path Traversal (`../`)** | Blocked by `os.Root` if it leads outside `rootDir`.          | Allowed by default, can lead to vulnerabilities if not handled carefully by the application. |
| **Absolute Imports**     | Allowed *only if* they resolve to a path *within* `rootDir`. Else `ErrForbiddenAbsolutePath`. | Allowed for any valid filesystem path.                  |
| **Symbolic Links**       | Following symlinks that point *outside* `rootDir` is blocked by `os.Root`. | Follows symlinks as per OS behavior.                     |
| **Null Byte Validation** | Paths containing null bytes are rejected with `ErrInvalidNullByte`. | No explicit null byte validation.                        |
| **Error Types**          | Specific errors for security violations (e.g., `ErrJPathOutsideRoot`, `ErrForbiddenAbsolutePath`, `ErrInvalidNullByte`). | Standard Go `os` errors, `jsonnet.RuntimeError` for import failures. |
| **Initialization**       | `safesonnet.NewSafeImporter(rootDir, jpaths, opts...)`       | `&jsonnet.FileImporter{JPaths: jpaths}`                  |
| **Caching Keys**         | Absolute filesystem paths for consistent cross-context lookups. | Typically absolute paths or paths as resolved by JPaths. |

## When to Use `SafeImporter`

-   **Untrusted Jsonnet Input**: If your application evaluates Jsonnet code or accepts import paths from untrusted users or external sources.
-   **Multi-tenant Systems**: When different tenants might provide Jsonnet files, and you need to isolate their file system access.
-   **Enhanced Security Posture**: For any application where limiting file system access during Jsonnet evaluation is a security requirement.
-   **Replacing `FileImporter` for Safety**: If you are currently using `FileImporter` and want to significantly improve the security of file imports without reimplementing complex path validation logic.
