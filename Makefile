# SPDX-FileCopyrightText: 2026 Mitsuru Kariya
# SPDX-License-Identifier: MIT

# Detect webkit2gtk version on Linux (Ubuntu 24.04+ / Debian bookworm+ uses 4.1)
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    ifneq ($(shell pkg-config --exists webkit2gtk-4.1 2>/dev/null && echo 1),)
        TAGS := -tags webkit2_41
    endif
endif

# Optional file path to open at startup
# Usage: make dev FILE=/usr/bin/ls
FILE     ?=
FILE_ARG := $(if $(FILE),-- $(FILE),)

.DEFAULT_GOAL := help

.PHONY: build dev web web-dev web-preview generate lint fmt release help

build:       ## Build the Wails desktop app
	wails build $(TAGS)

dev:         ## Start Wails dev mode with hot reload  (FILE=... to open a file)
	wails dev $(TAGS) $(FILE_ARG)

web:         ## Build the browser web version (output: frontend/dist/)
	cd frontend && npm run build

web-dev:     ## Start the browser web dev server (http://localhost:5173)
	cd frontend && npm run dev

web-preview: ## Preview the browser web build (http://localhost:4173)
	cd frontend && npm run preview

generate:    ## Regenerate wailsjs bindings after changing app.go
	wails generate module

lint:        ## Run ESLint
	cd frontend && npm run lint

fmt:         ## Format source files with Prettier
	cd frontend && npm run format

release:     ## Bump version and open a pull request to main  (VERSION=x.y.z required)
	@[ -n "$(VERSION)" ] || { printf "Error: VERSION is required.\nUsage: make release VERSION=x.y.z\n"; exit 1; }
	cd frontend && npm version "$(VERSION)" --no-git-tag-version
	git add frontend/package.json frontend/package-lock.json
	git commit -m "chore: bump version to $(VERSION)"
	git push
	gh pr create --title "chore: bump version to $(VERSION)" --body "" --base main

help:        ## Show this help
	@grep -E '^[a-zA-Z_-]+:[ \t]+##' $(MAKEFILE_LIST) | \
	 awk 'BEGIN {FS = ":[ \t]+## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
