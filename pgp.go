package pgp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

var DefaultConfig = &packet.Config{
	DefaultCipher: packet.CipherAES256,
}

// Symmetric provides convenience functions to create and parse
// symmetrically PGP and base64 encoded strings.
type Symmetric struct {
	cfg        *packet.Config
	passPhrase string
}

func NewSymmetric(cfg *packet.Config, passPhrase string) *Symmetric {
	if cfg == nil {
		cfg = DefaultConfig
	}
	return &Symmetric{cfg, passPhrase}
}

// Encode returns a URL escaped, base64 encoding of a symmetrically encrypted
// PGP cipher from msg.
func (s *Symmetric) Encode(msg string) (string, error) {
	var buf bytes.Buffer
	w, err := openpgp.SymmetricallyEncrypt(&buf, []byte(s.passPhrase), nil, s.cfg)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(w, msg)
	w.Close()
	return base64.URLEncoding.EncodeToString(buf.Bytes()), nil
}

// Decode expects a url escaped, base64 encoded PGP message.
func (s *Symmetric) Decode(msg string) (string, error) {
	cipher, err := base64.URLEncoding.DecodeString(msg)
	if err != nil {
		return "", err
	}
	firstKeyGetter := true
	md, err := openpgp.ReadMessage(
		bytes.NewBuffer(cipher),
		nil,
		func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
			if !firstKeyGetter {
				return nil, fmt.Errorf("symmetric decryption with passphrase failed due to multiple key read attempts")
			}
			if !symmetric {
				return nil, fmt.Errorf("pgp: non symmetric read attempt")
			}
			firstKeyGetter = false
			return []byte(s.passPhrase), nil
		},
		s.cfg,
	)
	if err != nil {
		return "", err
	}
	plain, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
