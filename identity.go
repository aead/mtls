// Copyright (c) 2024 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package mtls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strconv"
)

// ParseIdentity parses s and returns it as Identity.
//
// If s is the empty string, it returns the Identity zero
// value - for which IsZero returns true - and no error.
func ParseIdentity(s string) (Identity, error) {
	if s == "" {
		return Identity{}, nil
	}

	var i Identity
	if err := i.UnmarshalText([]byte(s)); err != nil {
		return Identity{}, err
	}
	return i, nil
}

// PeerIdentity returns the Identity of the peer's public key or
// an error if it did not provide any certificate during the TLS
// handshake.
//
// A TLS client should always receive a certificate containing the
// server's public key.
//
// A TLS server has to request a certificate and the client might
// not have one or choose to not send it.
func PeerIdentity(state *tls.ConnectionState) (Identity, error) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return Identity{}, IdentityError{}
	}
	return CertificateIdentity(state.PeerCertificates[0]), nil
}

// CertificateIdentity returns the identity of the certificate's
// public key.
func CertificateIdentity(cert *x509.Certificate) Identity {
	return Identity{
		hash: sha256.Sum256(cert.RawSubjectPublicKeyInfo),
	}
}

// An Identity is a cryptographic checksum over some data, usually a public key.
// Two identities, A and B, are equal when A == B is true.
//
// Its zero value is a valid identity but won't match any public key.
type Identity struct {
	hash [32]byte
}

var zeroIdentity = Identity{}

// IsZero returns true if i is the Identity zero value.
func (i Identity) IsZero() bool { return i == zeroIdentity }

// MarshalBinary returns a binary representation of the identity.
func (i Identity) MarshalBinary() ([]byte, error) {
	var buf [35]byte
	b := append(buf[:0], "h1:"...)
	return append(b, i.hash[:]...), nil
}

// UnmarshalBinary parses the binary representation of an identity.
func (i *Identity) UnmarshalBinary(b []byte) error {
	if !bytes.HasPrefix(b, []byte("h1:")) {
		return errors.New("mtls: invalid identity")
	}

	b = b[3:]
	if n := len(b); n != 32 {
		return errors.New("mtls: invalid identity length " + strconv.Itoa(n))
	}

	copy(i.hash[:], b)
	return nil
}

// MarshalText returns a textual representation of the identity.
func (i Identity) MarshalText() ([]byte, error) {
	var buf [46]byte
	b := append(buf[:0], "h1:"...)
	return base64.RawURLEncoding.AppendEncode(b, i.hash[:]), nil
}

// UnmarshalText parses the textual representation of an identity.
func (i *Identity) UnmarshalText(text []byte) error {
	if !bytes.HasPrefix(text, []byte("h1:")) {
		return errors.New("mtls: invalid identity")
	}
	text = text[3:]

	var dec [32]byte
	if n := base64.RawURLEncoding.DecodedLen(len(text)); n != len(dec) {
		return errors.New("mtls: invalid identity length " + strconv.Itoa(n))
	}
	n, err := base64.RawURLEncoding.Decode(dec[:], text)
	if err != nil {
		return err
	}
	if n != len(dec) {
		return errors.New("mtls: invalid identity length " + strconv.Itoa(n))
	}

	i.hash = dec
	return nil
}

// String returns a string representation of the identity.
//
// In contrast to [Identity.MarshalText], it returns the empty
// string if i is the zero value.
func (i Identity) String() string {
	if i.IsZero() {
		return ""
	}
	return "h1:" + base64.RawURLEncoding.EncodeToString(i.hash[:])
}

// IdentityError is an error that occurs when a peer does not provide a
// certificate during the TLS handshake or sends a public key that doesn't
// match an expected identity value.
type IdentityError struct {
	PeerIdentity Identity // Identity received from the connection peer
	Identity     Identity // Expected peer identity
}

// Error returns the IdentityError's error message.
func (e IdentityError) Error() string {
	var empty Identity
	if e.PeerIdentity == empty {
		return "mtls: no certificate provided by peer"
	}
	if e.Identity == empty {
		return "mtls: peer identity " + e.PeerIdentity.String() + " doesn't match"
	}
	return "mtls: peer identity " + e.PeerIdentity.String() + " doesn't match " + e.Identity.String()
}
