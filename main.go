// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

package main

import (
	"embed"
	"io/fs"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()

	// Pass CLI argument as initial path.
	if len(os.Args) > 1 {
		app.initPath = os.Args[1]
	}

	frontendFS, err := fs.Sub(assets, "frontend/dist")
	if err != nil {
		panic(err)
	}

	err = wails.Run(&options.App{
		Title:  "ELF Viewer",
		Width:  1024,
		Height: 768,
		AssetServer: &assetserver.Options{
			Assets: frontendFS,
		},
		OnStartup: app.startup,
		Bind: []interface{}{
			app,
		},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
