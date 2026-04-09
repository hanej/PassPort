package ad

import (
	"bytes"
	"testing"
)

func TestEncodePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     []byte
	}{
		{
			name:     "simple password",
			password: "password",
			// "password" wrapped in quotes => `"password"`
			// UTF-16LE encoding of each character:
			// "  => 0x22, 0x00
			// p  => 0x70, 0x00
			// a  => 0x61, 0x00
			// s  => 0x73, 0x00
			// s  => 0x73, 0x00
			// w  => 0x77, 0x00
			// o  => 0x6F, 0x00
			// r  => 0x72, 0x00
			// d  => 0x64, 0x00
			// "  => 0x22, 0x00
			want: []byte{
				0x22, 0x00, // "
				0x70, 0x00, // p
				0x61, 0x00, // a
				0x73, 0x00, // s
				0x73, 0x00, // s
				0x77, 0x00, // w
				0x6F, 0x00, // o
				0x72, 0x00, // r
				0x64, 0x00, // d
				0x22, 0x00, // "
			},
		},
		{
			name:     "empty password",
			password: "",
			// Just the two quote characters in UTF-16LE.
			want: []byte{0x22, 0x00, 0x22, 0x00},
		},
		{
			name:     "password with special chars",
			password: "P@ss!",
			want: []byte{
				0x22, 0x00, // "
				0x50, 0x00, // P
				0x40, 0x00, // @
				0x73, 0x00, // s
				0x73, 0x00, // s
				0x21, 0x00, // !
				0x22, 0x00, // "
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodePassword(tt.password)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("EncodePassword(%q)\n  got  %v\n  want %v", tt.password, got, tt.want)
			}
		})
	}
}
