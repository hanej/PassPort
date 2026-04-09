package ad

import (
	"encoding/binary"
	"unicode/utf16"
)

// EncodePassword encodes a password for Active Directory's unicodePwd attribute.
// AD requires the password to be wrapped in double quotes and encoded as UTF-16LE.
func EncodePassword(password string) []byte {
	quoted := "\"" + password + "\""
	encoded := utf16.Encode([]rune(quoted))

	buf := make([]byte, len(encoded)*2)
	for i, r := range encoded {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return buf
}
