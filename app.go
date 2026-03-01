// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/base64"
	"os"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct provides methods bound to the frontend.
type App struct {
	ctx      context.Context
	initPath string // optional path passed via CLI
}

// NewApp creates a new App instance.
func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// OpenFileDialog shows a native file selection dialog.
func (a *App) OpenFileDialog() (string, error) {
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select ELF File",
	})
}

// GetInitPath returns the initial file path if one was passed via CLI.
func (a *App) GetInitPath() string {
	return a.initPath
}

// ReadFileBytes reads a file from the local filesystem and returns its content
// as a base64-encoded string. Returning []byte directly causes Wails/Go's JSON
// marshaler to also base64-encode it, but the generated TypeScript type would
// incorrectly say Array<number>. Returning string makes the contract explicit.
func (a *App) ReadFileBytes(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}
