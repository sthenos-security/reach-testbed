// Fixture: CWE-502 Deserialization - Go
// VERDICT: TRUE_POSITIVE
// PATTERN: gob_decode_untrusted_source
// SOURCE: network_connection
// SINK: gob.Decoder.Decode
// TAINT_HOPS: 1
// NOTES: encoding/gob from untrusted network connection
package rpc

import (
	"encoding/gob"
	"net"
)

type Command struct {
	Action string
	Args   []string
}

func HandleConnection(conn net.Conn) (*Command, error) {
	var cmd Command
	dec := gob.NewDecoder(conn)
	// VULNERABLE: deserializing from untrusted network source
	err := dec.Decode(&cmd)
	return &cmd, err
}
