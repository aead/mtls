// Copyright (c) 2024 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package mtls_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"aead.dev/mtls"
)

// TestGenerateKeyEdDSA tests whether generated EdDSA private keys
// are equal to their parsed textual representation
func TestGenerateKeyEdDSA(t *testing.T) {
	t.Parallel()

	key, err := mtls.GenerateKeyEdDSA(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EdDSA private key: %v", err)
	}

	s := key.String()
	key2, err := mtls.ParsePrivateKey(s)
	if err != nil {
		t.Fatalf("failed to unmarshal EdDSA private key %s: %v", s, err)
	}
	if k := key.Private().(ed25519.PrivateKey); !k.Equal(key2.Private()) {
		t.Fatalf("private keys are not equal: %s != %s", key, key2)
	}
}

// TestGenerateKeyECDSA tests whether generated ECDSA private keys
// are equal to their parsed textual representation for all supported
// curves.
func TestGenerateKeyECDSA(t *testing.T) {
	t.Parallel()

	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}
	for _, curve := range curves {
		key, err := mtls.GenerateKeyECDSA(curve, rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA private key for curve %s: %v", curve.Params().Name, err)
		}

		s := key.String()
		key2, err := mtls.ParsePrivateKey(s)
		if err != nil {
			t.Fatalf("failed to unmarshal ECDSA private key %s: %v", s, err)
		}
		if k := key.Private().(*ecdsa.PrivateKey); !k.Equal(key2.Private()) {
			t.Fatalf("private keys are not equal: %s != %s", key, key2)
		}
	}
}
