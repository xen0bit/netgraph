package wifi

import "testing"

func FuzzWEPDecrypt(f *testing.F) {
	f.Add([]byte{0, 1, 2, 0, 3, 4, 5, 6, 7, 8})
	f.Fuzz(func(t *testing.T, body []byte) {
		keys := [4][]byte{make([]byte, 13), nil, nil, nil}
		_, _ = wepDecrypt(body, keys)
	})
}

func FuzzTKIPDecrypt(f *testing.F) {
	f.Add(make([]byte, 24), []byte{0, 1, 2, 0x20, 0, 0, 0, 0, 9, 8, 7, 6, 5, 4, 3, 2}, make([]byte, 32))
	f.Fuzz(func(t *testing.T, header, body, tk []byte) {
		_, _ = tkipDecrypt(header, body, tk, true)
	})
}
