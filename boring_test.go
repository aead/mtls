// Copyright (c) 2024 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

//go:build boringcrypto

package mtls_test

import (
	"testing"

	"aead.dev/mtls"
)

func TestBoringCrypto(t *testing.T) {
	const Key = "k1:xZnpcYtPdVMNLBBRaUO5HPEoK_jVrcc3MWR8BshkjJw"

	if _, err := mtls.ParsePrivateKey(Key); err == nil {
		t.Fatal("Parsed Ed25519 private key in FIPS mode successfully")
	}

	if _, err := mtls.GenerateKeyEdDSA(nil); err == nil {
		t.Fatal("Generated Ed25519 private key in FIPS mode successfully")
	}

	var k mtls.EdDSAPrivateKey
	if err := k.UnmarshalText([]byte(Key)); err == nil {
		t.Fatal("Unmarshaled Ed25519 private key in FIPS mode successfully")
	}

	if _, err := k.MarshalText(); err == nil {
		t.Fatal("Marshaled Ed25519 private key in FIPS mode successfully")
	}
}
