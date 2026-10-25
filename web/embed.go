//go:build embed_web

package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

func init() {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	FS = sub
}
