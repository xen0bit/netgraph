//go:build linux && (mips || mips64 || ppc64 || s390x)

package bpf

import _ "embed"

//go:embed conn_bpfeb.o
var object []byte
