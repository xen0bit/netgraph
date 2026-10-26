package wifi

import (
	"encoding/hex"
	"testing"
)

func TestAESCMACRFC4493(t *testing.T) {
	key := mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	for _, tc := range []struct{ msg, want string }{
		{"", "bb1d6929e95937287fa37d129b756746"},
		{"6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
		{"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411", "dfa66747de9ae63030ca32611497c827"},
	} {
		got := aesCMAC(key, mustHex(t, tc.msg))
		if hex.EncodeToString(got[:]) != tc.want {
			t.Errorf("CMAC(%s) = %x, want %s", tc.msg, got, tc.want)
		}
	}
}
