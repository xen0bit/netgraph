//go:build linux && (386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64)

package bpf

import _ "embed"

//go:embed conn_bpfel.o
var object []byte
