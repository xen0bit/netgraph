// Package web holds the browser UI. Its sources are in src/; `make
// web.build` assembles them with the WASM module into dist/, which builds
// tagged embed_web compile into the binary.
package web

import "io/fs"

// FS is the built UI, or nil when this binary was built without
// embed_web.
var FS fs.FS
