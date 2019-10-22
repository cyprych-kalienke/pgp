package pgp

import (
	"testing"
)

const testPlain = "my message"
const testPass = "passphrase"
const testCipher = "wy4ECQMI6uS3eNtRoABg-U3zY5DnrZV8sMFfgz9rIr6NpEnK8ZD3r6EA4Bc_ZZzS0uAB5JnzqkQpRMzwkMBf-SIng4XhZsPgjeBv4Uui4HTigLTjkuAx48KsY77yup1u4FPhC6ng0uSyTpuV-KsHC9vvgDArvc8Q4nRRfP3hU0IA"

func TestSymmEncode(t *testing.T) {
	s := NewSymmetric(nil, testPass)
	enc, err := s.Encode(testPlain)
	if err != nil {
		t.Error(err)
		return
	}
	if len(enc) == 0 {
		t.Errorf("got empty string when encoding plaintext message")
	}
}

func TestSymmDecode(t *testing.T) {
	s := NewSymmetric(nil, testPass)
	dec, err := s.Decode(testCipher)
	if err != nil {
		t.Error(err)
		return
	}
	if dec != testPlain {
		t.Errorf("expected test cipher %q to result in plain text %q, got %q", testCipher, testPass, dec)
	}
}
