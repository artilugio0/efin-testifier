# AGENTS.md - efin-testifier

This file contains build/lint/test commands and code style guidelines for the efin-testifier codebase.

## Build Commands

- **Build binary**: `./scripts/buid.sh` (note: script has typo in filename)
- **Go build**: `CGO_ENABLED=0 go build -o build/efin-testifier ./cmd/efin-testifier`
- **Clean build**: `go clean && go mod tidy && go build ./cmd/efin-testifier`
- **Cross-platform build**: `GOOS=linux GOARCH=amd64 go build ./cmd/efin-testifier`

## Test Commands

- **Run all tests in a Lua file**: `./efin-testifier example_test.lua`
- **Run specific test**: `./efin-testifier example_test.lua -t "test_get_example"`
- **Run tests matching regex**: `./efin-testifier example_test.lua -t "test_.*_api"`
- **Run with custom RPS**: `./efin-testifier example_test.lua -r 10`
- **Go module tests**: `go test ./...` (if any Go unit tests exist)

## Lint Commands

- **Go fmt**: `go fmt ./...`
- **Go vet**: `go vet ./...`
- **Go mod tidy**: `go mod tidy`
- **Combined lint**: `go fmt ./... && go vet ./... && go mod tidy`

## Code Style Guidelines

### Imports
- Group imports: standard library first, then third-party packages, then local packages
- Use blank lines between groups
- Example:
```go
import (
    "fmt"
    "os"
    "path/filepath"

    "github.com/spf13/cobra"
    lua "github.com/yuin/gopher-lua"

    "github.com/artilugio0/efin-testifier/pkg/liblua"
)
```

### Naming Conventions
- **Functions/Methods**: PascalCase for exported, camelCase for unexported
- **Structs/Types**: PascalCase
- **Constants**: PascalCase
- **Variables**: camelCase
- **Package names**: lowercase, single word when possible

### Formatting
- Use `gofmt` or `go fmt` for automatic formatting
- 4-space indentation (Go standard)
- No trailing commas in multi-line structs/slices
- Line length: reasonable, break long lines appropriately

### Error Handling
- Return errors from functions rather than panicking
- Use `fmt.Errorf` for error wrapping: `fmt.Errorf("Error: %v", err)`
- Check errors immediately after operations
- Use early returns for error conditions

### Comments
- Add brief comments for exported functions, structs, and types
- Use `//` for single-line comments
- Comments should explain purpose, not implementation details

### Structs and Types
- Define types before functions that use them
- Group related types together
- Use meaningful field names with appropriate types

### Constants
- Group related constants together
- Use meaningful names
- Example:
```go
const (
    DefaultRequestsPerSecond float64 = 20.0
)
```

### Function Organization
- Exported functions first, then unexported
- Group related functions together
- Keep functions reasonably sized; break large functions into smaller ones

### Lua Integration
- Lua scripts use snake_case for function names (test_*, register_*, etc.)
- Go code interfacing with Lua should handle both camelCase and snake_case appropriately
- Use proper error handling when calling Lua functions

### Dependencies
- Use Go modules for dependency management
- Keep dependencies minimal and well-maintained
- Check go.mod for current dependencies before adding new ones