//go:build !embed_asn

package asn

// Without the embed_asn tag (go install, go build) there is no built-in
// table: the server uses -asn-file, or none.
func embeddedTable() ([]byte, string) { return nil, "" }
