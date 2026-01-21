# AGENTS.md - Development Guide for OAuth Example

## Project Overview

**OAuth 2.0 Server** built with Ory Fosite framework, implementing:
- Standard OAuth 2.0 flows (Authorization Code, Refresh Token, Token Revocation)
- Custom grant types: Security Token Obtain, Token Exchange (RFC 8693)
- Valkey (Redis-compatible) for token storage
- Memory-based client storage

**Language:** Go 1.25.2  
**Server Port:** 8080  
**Endpoints:** `/oauth2/authorization`, `/oauth2/token`, `/oauth2/revoke`

---

## Build & Run Commands

### Docker Compose (Primary Development Method)

```bash
# Start all services (OAuth server, Valkey, Kratos, Kratos UI)
docker compose up -d

# View logs
docker compose logs -f

# Stop all services
docker compose down

# Rebuild and restart
docker compose up -d --build
```

**Environment Variables Required:**
- `VALKEY_ADDRESS` (required) - e.g., "localhost:6379"
- `VALKEY_PASSWORD` (optional) - default: "mypassword"
- `VALKEY_USERNAME` (optional)
- `VALKEY_DB` (optional) - default: 0

### Go Commands

```bash
# Build the OAuth server binary
go build -o oauth-server .

# Run directly (requires Valkey running separately)
go run main.go

# Format code (always run before committing)
go fmt ./...

# Update dependencies
go mod tidy

# Verify dependencies
go mod verify
```

---

## Testing Commands

**Note:** Currently no test files exist in this project. When tests are added, use:

```bash
# Run all tests
go test ./...

# Run tests for specific package
go test ./store/valkey
go test ./extension

# Run single test by name
go test -v -run TestCreateAccessTokenSession ./store/valkey

# Run with coverage
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run with race detection
go test -race ./...

# Verbose output
go test -v ./...
```

---

## Code Style Guidelines

### Import Organization

**Order:** Standard library → Local packages → Third-party packages  
**Separation:** Single blank line between groups  
**Sorting:** Alphabetical within each group

```go
import (
    // 1. Standard library
    "context"
    "crypto/rand"
    "fmt"
    "time"
)

import (
    // 2. Local packages
    "ch0wdreN/oauth-example/extension"
    memoryclient "ch0wdreN/oauth-example/store/memory_client"
    "ch0wdreN/oauth-example/store/valkey"
)

import (
    // 3. Third-party packages
    json "github.com/goccy/go-json"
    "github.com/ory/fosite"
    "github.com/ory/fosite/handler/oauth2"
    "github.com/valkey-io/valkey-go"
)
```

**Alias Usage:**
- Use aliases for disambiguation: `json "github.com/goccy/go-json"`
- Use aliases for long package names: `memoryclient "ch0wdreN/oauth-example/store/memory_client"`

### Naming Conventions

| Pattern | Example | Usage |
|---------|---------|-------|
| `New*` | `NewValkeyClient()`, `NewMemoryClientStore()` | Constructors |
| `Valkey*Storage` | `ValkeyAccessTokenStorage` | Valkey-backed storage implementations |
| `*Store` | `MemoryClientStore` | Generic stores |
| `*Handler` | `tokenExchangeHandler` (private) | Grant type handlers |
| `*HandlerFactory` | `TokenExchangeHandlerFactory` (public) | Factory functions |
| `*Key()` | `accessTokenKey()`, `refreshTokenKey()` | Key generation helpers |
| `Can*`, `Is*`, `Has*` | `CanHandleTokenEndpointRequest()` | Boolean methods |

### Type Definitions

**Compile-time Interface Checks** (always use for interface implementations):
```go
var _ oauth2.AccessTokenStorage = &ValkeyAccessTokenStorage{}
var _ fosite.TokenEndpointHandler = &tokenExchangeHandler{}
```

**Interface Embedding** (for composition):
```go
type ValkeyAccessTokenStorage struct {
    client *ValkeyClient
    fosite.ClientManager  // Embedded for GetClient()
    accessTokenLifespan time.Duration
}
```

**Struct Tags for Environment Parsing:**
```go
type ValkeyConfig struct {
    Address  string `env:"VALKEY_ADDRESS,required"`
    Username string `env:"VALKEY_USERNAME"`
    Password string `env:"VALKEY_PASSWORD"`
    DB       int    `env:"VALKEY_DB" envDefault:"0"`
}
```

### Error Handling

**Pattern 1: Standard Go Error Wrapping** (most common):
```go
if err != nil {
    return fmt.Errorf("failed to create valkey client: %w", err)
}
```

**Pattern 2: Fosite Error Handling** (in OAuth handlers):
```go
return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("access_token is required"))

// With wrapping and debug info
return errorsx.WithStack(
    fosite.ErrInvalidRequest.
        WithHint("subject_token must be a valid base64 encoded string").
        WithWrap(err).
        WithDebug(err.Error()),
)
```

**Pattern 3: Valkey Nil Checks** (for Redis operations):
```go
result, err := v.client.Do(ctx, cmd).AsReader()
if valkey.IsValkeyNil(err) {
    return nil, fosite.ErrNotFound
}
if err != nil {
    return nil, fmt.Errorf("failed to get access token: %w", err)
}
```

**HTTP Handler Error Pattern:**
```go
ar, err := provider.NewAuthorizeRequest(ctx, r)
if err != nil {
    log.Printf("Error occurred in NewAuthorizeRequest: %+v", err)
    provider.WriteAuthorizeError(ctx, w, ar, err)
    return
}
```

**NEVER:**
- Use `as any` for type assertions (use proper interface checks)
- Suppress errors silently without logging
- Use `panic()` except in initialization functions like `mustGenerateKey()`

### Context Usage

- **Always first parameter** in function signatures: `func Method(ctx context.Context, ...)`
- Pass context through all layers (storage → handler → HTTP)
- Use context-aware logging: `slog.ErrorContext(ctx, "message", "error", err)`
- Extract context in HTTP handlers: `ctx := r.Context()`

### Logging

Use `log/slog` for structured logging:

```go
// Debug level (verbose information)
slog.Debug("Access token validated successfully")
slog.Debug("Generated signature", "signature", signature)

// Error level (with error object)
slog.Error("Failed to get access token session", "error", err, "signature", signature)
slog.ErrorContext(ctx, "error occurred", "error", err.Error())
```

**Prefer structured logging over fmt:**
- ✅ `slog.Debug("message", "key", value)`
- ❌ `log.Printf("message %v", value)`

### Comments

**Interface Implementation Comments** (required):
```go
// CreateAccessTokenSession implements oauth2.AccessTokenStorage.
func (v *ValkeyAccessTokenStorage) CreateAccessTokenSession(...)
```

**Godoc for Exported Functions:**
```go
// NewValkeyClient creates a new Valkey-based storage
func NewValkeyClient(ctx context.Context, cfg *ValkeyConfig) (*ValkeyClient, error)
```

**TODO Comments:**
- Currently some TODO comments exist in Japanese
- Prefer English for consistency: `// TODO: Implement audience verification logic`

---

## Project Structure

```
oauth-example/
├── main.go                      # Application entry point
│                                # - HTTP server setup
│                                # - OAuth provider configuration
│                                # - JWT strategy & RSA key generation
│
├── extension/                   # Custom OAuth grant type implementations
│   ├── flow_obtain.go           # Security Token Obtain grant
│   │                            # urn:your-company:params:oauth:grant-type:security-token-obtain
│   └── flow_exchange.go         # Token Exchange grant (RFC 8693)
│                                # urn:ietf:params:oauth:grant-type:token-exchange
│
├── store/                       # Storage layer implementations
│   ├── valkey/                  # Valkey (Redis-compatible) storage
│   │   ├── valkey.go            # Client wrapper & config
│   │   ├── access_token.go      # Access token CRUD + indexing
│   │   ├── refresh_token.go     # Refresh token CRUD + rotation
│   │   ├── code.go              # Authorization code storage
│   │   ├── token_revocation.go  # Token revocation logic
│   │   └── util.go              # Redis key naming helpers
│   │
│   └── memory_client/           # In-memory client store
│       └── memory.go            # Pre-configured clients (service-a, service-b)
│
├── kratos/                      # Ory Kratos identity management
│   └── config/
│       ├── kratos.yaml          # Kratos server configuration
│       └── identity.schema.json # User identity schema
│
├── compose.yaml                 # Docker Compose for full stack
├── go.mod                       # Go module definition
└── users.acl                    # Valkey ACL configuration
```

---

## Key Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `github.com/ory/fosite` | v0.49.0 | OAuth 2.0/OIDC server framework |
| `github.com/valkey-io/valkey-go` | v1.0.69 | Redis-compatible Valkey client |
| `github.com/goccy/go-json` | v0.10.5 | Fast JSON marshaling/unmarshaling |
| `github.com/caarlos0/env/v11` | v11.3.1 | Environment variable parsing |
| `github.com/ory/x` | v0.0.665 | Error handling utilities (errorsx) |

**Test Dependencies** (not currently used):
- `github.com/stretchr/testify` v1.9.0 - Testing assertions & mocks

---

## Development Notes

### Missing Tooling (Recommendations)

- **No linter config** - Consider adding `.golangci.yml` for consistent code quality
- **No CI/CD** - No GitHub Actions or similar automation
- **No tests** - Test files should be added for all storage implementations and handlers
- **No Makefile** - All commands are run via `go` or `docker compose`

### Local Development Workflow

1. **Start infrastructure:** `docker compose up -d` (starts Valkey, Kratos, etc.)
2. **Run OAuth server:** `go run main.go`
3. **Make changes:** Edit code, run `go fmt ./...`
4. **Verify:** Check for compilation errors, run linter if available
5. **Test manually:** Use curl or Postman against `localhost:8080/oauth2/*`

### Common Development Tasks

**Adding a new storage implementation:**
1. Create file in `store/` directory
2. Implement required Fosite interfaces
3. Add compile-time interface check: `var _ Interface = &Type{}`
4. Follow error handling patterns (fmt.Errorf with %w)
5. Use slog for logging

**Adding a new grant type:**
1. Create file in `extension/` directory
2. Implement `fosite.TokenEndpointHandler` interface
3. Create factory function: `*HandlerFactory`
4. Register in `main.go` with `compose.Compose(...)`

---

**Generated for AI coding agents operating in this repository.**
