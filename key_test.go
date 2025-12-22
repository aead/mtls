// Copyright (c) 2024 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package mtls_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
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

// TestGenerateKeyRSA tests whether generated RSA private keys
// are equal to their parsed textual representation for common
// key sizes.
func TestGenerateKeyRSA(t *testing.T) {
	t.Parallel()

	bitSizes := []int{2048, 3072, 4096}
	for _, bits := range bitSizes {
		key, err := mtls.GenerateKeyRSA(rand.Reader, bits)
		if err != nil {
			t.Fatalf("failed to generate %d RSA private key: %v", bits, err)
		}

		s := key.String()
		key2, err := mtls.ParsePrivateKey(s)
		if err != nil {
			t.Fatalf("failed to unmarshal %d RSA private key %s: %v", bits, s, err)
		}
		if k := key.Private().(*rsa.PrivateKey); !k.Equal(key2.Private()) {
			t.Fatalf("private keys are not equal: %s != %s", key, key2)
		}
	}
}

// TestPrivateKey_Identity checks that a certificate's public key identity of matches the
// identity of the corresponding private key.
func TestPrivateKey_Identity(t *testing.T) {
	t.Parallel()

	for _, test := range privateKeyIdentityTests {
		key, err := mtls.ParsePrivateKey(test.PrivateKey)
		if err != nil {
			t.Fatalf("failed to parse private key %s: %v", test.PrivateKey, err)
		}

		b, err := os.ReadFile(test.Filename)
		if err != nil {
			t.Fatal(err)
		}

		block, _ := pem.Decode(b)
		if block.Type != "CERTIFICATE" {
			t.Fatalf("failed to decode file %s as PEM certificate", test.Filename)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse certificate %s: %v", test.Filename, err)
		}

		id := mtls.CertificateIdentity(cert)
		if id != key.Identity() {
			t.Fatalf("identity mismatch for %s: %s != %s", test.Filename, id, key.Identity())
		}
	}
}

var privateKeyIdentityTests = []struct {
	Filename   string
	PrivateKey string
}{
	{
		Filename:   "./testdata/certs/ed25519.crt",
		PrivateKey: "k1:xZnpcYtPdVMNLBBRaUO5HPEoK_jVrcc3MWR8BshkjJw",
	},
	{
		Filename:   "./testdata/certs/p-256.crt",
		PrivateKey: "k2:q0B1BZ069Sk3-pBun983nLbQUOSR_j0ltnkfG4nPrE0",
	},
	{
		Filename:   "./testdata/certs/p-384.crt",
		PrivateKey: "k2:CaJIp1tfO7US1bMkRP1LzVzMV8v4IK5oBW1bhuvJFpFOPtbsJf3a3vViu5uGSas6",
	},
	{
		Filename:   "./testdata/certs/p-521.crt",
		PrivateKey: "k2:AT7JYw3tnjgYhqplUPiJbITqAdgo4IuDf9talnHivzMeoEsVR60Vidpl93zAdweZApsStCEpHVPtwGAD2UoGI0o0",
	},
	{
		Filename:   "./testdata/certs/rsa.crt",
		PrivateKey: "k3:AAQAAQABAIDIgYr4PXOsMUpeV-tjoVEs5h6iCudZAkbWA8o3m9C40tIc3ZKPxANNrNDQBv_aQxJsbEvZ8CWgRKuSP3kcFZq1f96Zra99PBvrypAlhtwzehmDUIDJQwlshNIozBRTL_zHFZDKIjMSwiag3bWQmm_ivuNfL-WWIkUpXNU1NvEsWwCAtkeD1ZsCAF1t-_wPl-iHspI-qLz43B1Op2Z7ja-aIYvViYig7a7e_yyr_RR3PePpOiQMcz4HMtWkf3BbyGwSZWm4wlIcNBrLP0oEpDx1sIh1D7yg9aquDiyYuQwFjZwTMP0Vy4KSoz3U1USM-EEICTyM8qBsBp8mGUkOl26ZS2kBAERYqSbToPba3HeNFITdv9_9PLoUsFYl3wKFLNdDDNredfGpkmgeyGl4BLOJ_BR2tNDWbzspLJ45slAe9e-FB5VIgk7lwd_eHBuNSODbUpTkNmge6ZEunQa3j5Yuvh9LxBg-Gwbnm3kSdt8Q0YqrZTwSZMiogAN6aqI1GwjNRHx_8M9718mSGAmlYWHAfXsgxVr3VTMtZjYmGB2_Slu46M4k58Mf2QrOgP9iGz6ED7q2CL3_PIAT1Ce0qKf3UP8IgVm6ENJx5obKdq2UeyV3OQx5HL99_X74f6KjjVtd1XXjrxoSqBP_HZYce8K1FgWjpFMshsPTAHGrsmk_dseDfSk",
	},
}
