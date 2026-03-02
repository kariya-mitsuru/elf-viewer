# CLAUDE.md — ELF Viewer

## Architecture

Wails v2 desktop app with Go backend and TypeScript frontend.

- **Go backend** (`app.go`): minimal — only `OpenFileDialog`, `GetInitPath`, `ReadFileBytes`, `startup`
- **TypeScript frontend** (`frontend/src/`): all ELF parsing, rendering, and UI logic
- **Parser** (`frontend/src/parser/`): DataView-based ELF32/64 parser, LSB/MSB support
- **Build output**: `frontend/dist/` — single HTML file via `vite-plugin-singlefile`

## Key Patterns

- Use `enum`, NOT `const enum` — incompatible with `isolatedModules: true`
- Default switch branches on enum values may need `(value as number)` to avoid `never` type errors
- Wails runtime detection: `'go' in window`
- `ReadFileBytes` returns `Array<number>` from Go → convert with `new Uint8Array(bytes)`

## Development Commands

```sh
make dev            # Wails dev mode (hot reload)
make dev FILE=...   # Open a specific file at startup
make web            # Build frontend only (frontend/dist/)
make web-dev        # Vite dev server (http://localhost:5173)
make lint           # ESLint
make fmt            # Prettier
make build          # Build Wails desktop app
```

## Release Process

Version is tracked in `frontend/package.json`.

```sh
make release VERSION=x.y.z
```

This will:
1. Update `frontend/package.json` version via `npm version`
2. Commit and push to the current branch (`dev`)
3. Open a PR to `main`

On merge to `main`, the `auto-tag` workflow creates `vX.Y.Z` tag automatically,
which triggers the `release` workflow to build and publish GitHub Releases.
