// Copyright (c) 2024 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package mtls

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// PrivateKey is private key for TLS and mutual TLS connections.
type PrivateKey interface {
	// Private returns the PrivateKey's cryptographic private key.
	Private() crypto.PrivateKey

	// Public returns the PrivateKey's cryptographic public key.
	Public() crypto.PublicKey

	// Identity returns the PrivateKey's [Identity]. It identifies
	// the cryptographic public key.
	Identity() Identity

	// String returns a string representation of the PrivateKey.
	String() string
}

// ParsePrivateKey parses s and returns it as PrivateKey.
//
// Currently, ParsePrivateKey either returns a *EdDSAPrivateKey,
// a *ECDSAPrivateKey or an error.
func ParsePrivateKey(s string) (PrivateKey, error) {
	switch {
	default:
		return nil, errors.New("mtls: invalid private key")

	case strings.HasPrefix(s, "k1:"):
		var key EdDSAPrivateKey
		if err := key.UnmarshalText([]byte(s)); err != nil {
			return nil, err
		}
		return &key, nil

	case strings.HasPrefix(s, "k2:"):
		var key ECDSAPrivateKey
		if err := key.UnmarshalText([]byte(s)); err != nil {
			return nil, err
		}
		return &key, nil
	}
}

// EdDSAPrivateKey is a [PrivateKey] for the EdDSA signature algorithm
// as specified in RFC 8032.
type EdDSAPrivateKey struct {
	priv     ed25519.PrivateKey
	identity Identity
}

// GenerateKeyEdDSA generates a new [EdDSAPrivateKey] using entropy
// from random. If random is nil, [crypto/rand.Reader] will be used.
func GenerateKeyEdDSA(random io.Reader) (*EdDSAPrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}
	pub, priv, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, err
	}
	identity, err := ed25519Identity(pub)
	if err != nil {
		return nil, err
	}

	return &EdDSAPrivateKey{
		priv:     priv,
		identity: identity,
	}, nil
}

// Private returns the EdDSA private key.
func (pk *EdDSAPrivateKey) Private() crypto.PrivateKey {
	priv := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(priv, pk.priv)
	return priv
}

// Public returns the EdDSA public key.
func (pk *EdDSAPrivateKey) Public() crypto.PublicKey {
	return pk.priv.Public()
}

// Identity returns the identity of the EdDSA public key.
func (pk *EdDSAPrivateKey) Identity() Identity {
	return pk.identity
}

// MarshalText returns a textual representation of the private key.
//
// It returns output equivalent to [EdDSAPrivateKey.String]
func (pk *EdDSAPrivateKey) MarshalText() ([]byte, error) {
	var text [46]byte
	b := append(text[:0], "k1:"...)
	b = base64.RawURLEncoding.AppendEncode(b, pk.priv[:ed25519.SeedSize])
	return b, nil
}

// UnmarshalText parses a private key textual representation.
func (pk *EdDSAPrivateKey) UnmarshalText(text []byte) error {
	if !bytes.HasPrefix(text, []byte("k1:")) {
		return errors.New("mtls: invalid EdDSA private key")
	}
	text = text[3:]

	var dec [32]byte
	if n := base64.RawURLEncoding.DecodedLen(len(text)); n != len(dec) {
		return errors.New("mtls: invalid EdDSA private key length " + strconv.Itoa(n))
	}
	n, err := base64.RawURLEncoding.Decode(dec[:], text)
	if err != nil {
		return err
	}
	if n != len(dec) {
		return errors.New("mtls: invalid EdDSA private key length " + strconv.Itoa(n))
	}

	priv := ed25519.NewKeyFromSeed(dec[:])
	identity, err := ed25519Identity(ed25519.PublicKey(priv[ed25519.SeedSize:]))
	if err != nil {
		return err
	}
	pk.priv, pk.identity = priv, identity
	return nil
}

// String returns a string representation of the private key.
//
// Its output is equivalent to [EdDSAPrivateKey.MarshalText]
func (pk *EdDSAPrivateKey) String() string {
	return "k1:" + base64.RawURLEncoding.EncodeToString(pk.priv[:ed25519.SeedSize])
}

// GenerateKeyECDSA generates a new [ECDSAPrivateKey] for the given elliptic curve
// using entropy from random. If rand is nil, [crypto/rand.Reader] will be used.
//
// Currently, only the NIST curves P-256, P-384 and P-521 are supported.
func GenerateKeyECDSA(curve elliptic.Curve, random io.Reader) (*ECDSAPrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}

	switch curve {
	default:
		return nil, errors.New("mtls: curve " + curve.Params().Name + " is not supported")
	case elliptic.P256():
	case elliptic.P384():
	case elliptic.P521():
	}

	priv, err := ecdsa.GenerateKey(curve, random)
	if err != nil {
		return nil, err
	}
	identity, err := ecdsaIdentity(priv)
	if err != nil {
		return nil, err
	}

	return &ECDSAPrivateKey{
		priv:     *priv,
		identity: identity,
	}, nil
}

// ECDSAPrivateKey is a [PrivateKey] for the elliptic curve digital
// signature algorithm as specified in FIPS 186-4 and SEC 1, Version 2.0.
type ECDSAPrivateKey struct {
	priv     ecdsa.PrivateKey
	identity Identity
}

// Private returns the ECDSA private key.
func (pk *ECDSAPrivateKey) Private() crypto.PrivateKey {
	var D, X, Y big.Int
	return &ecdsa.PrivateKey{
		D: D.Set(pk.priv.D),
		PublicKey: ecdsa.PublicKey{
			Curve: pk.priv.PublicKey.Curve,
			X:     X.Set(pk.priv.PublicKey.X),
			Y:     Y.Set(pk.priv.PublicKey.Y),
		},
	}
}

// Private returns the ECDSA public key.
func (pk *ECDSAPrivateKey) Public() crypto.PublicKey {
	var X, Y big.Int
	return &ecdsa.PublicKey{
		Curve: pk.priv.PublicKey.Curve,
		X:     X.Set(pk.priv.PublicKey.X),
		Y:     Y.Set(pk.priv.PublicKey.Y),
	}
}

// Identity returns the identity of the ECDSA public key.
func (pk *ECDSAPrivateKey) Identity() Identity { return pk.identity }

// MarshalText returns a textual representation of the private key.
//
// It returns output equivalent to [ECDSAPrivateKey.String]
func (pk *ECDSAPrivateKey) MarshalText() ([]byte, error) {
	// We use FillBytes instead of Bytes since the later returns
	// a variable-size slice. However, we want all private key
	// representations to be of a fixed length. A P-521 private
	// key is at most 66 bytes long.
	var p [66]byte
	priv := pk.priv.D.FillBytes(p[:])
	priv = priv[66-(pk.priv.Curve.Params().BitSize+7)/8:]

	var buf [3 + 88]byte
	b := append(buf[:0], "k2:"...)
	b = base64.RawURLEncoding.AppendEncode(b, priv)
	return b, nil
}

// UnmarshalText parses an private key textual representation.
func (pk *ECDSAPrivateKey) UnmarshalText(text []byte) error {
	if !bytes.HasPrefix(text, []byte("k2:")) {
		return errors.New("mtls: invalid ECDSA private key")
	}
	text = text[3:]

	var (
		curveDH ecdh.Curve
		curveEC elliptic.Curve
		n       = base64.RawURLEncoding.DecodedLen(len(text))
	)
	switch n {
	default:
		return errors.New("mtls: invalid ECDSA private key length " + strconv.Itoa(n))
	case 32:
		curveDH, curveEC = ecdh.P256(), elliptic.P256()
	case 48:
		curveDH, curveEC = ecdh.P384(), elliptic.P384()
	case 66:
		curveDH, curveEC = ecdh.P521(), elliptic.P521()
	}

	dec := make([]byte, n)
	nn, err := base64.RawURLEncoding.Decode(dec, text)
	if err != nil {
		return err
	}
	if n != nn {
		return errors.New("mtls: invalid EdDSA private key length " + strconv.Itoa(nn))
	}

	ecdhKey, err := curveDH.NewPrivateKey(dec)
	if err != nil {
		return err
	}

	D := new(big.Int).SetBytes(ecdhKey.Bytes())
	X, Y := curveEC.ScalarBaseMult(ecdhKey.Bytes())
	priv := ecdsa.PrivateKey{
		D: D,
		PublicKey: ecdsa.PublicKey{
			Curve: curveEC,
			X:     X,
			Y:     Y,
		},
	}

	identity, err := ecdsaIdentity(&priv)
	if err != nil {
		return err
	}

	pk.priv, pk.identity = priv, identity
	return nil
}

// String returns a string representation of the private key.
//
// Its output is equivalent to [ECDSAPrivateKey.MarshalText]
func (pk *ECDSAPrivateKey) String() string {
	// We use FillBytes instead of Bytes since the later returns
	// a variable-size slice. However, we want all private key
	// representations to be of a fixed length. A P-521 private
	// key is at most 66 bytes long.
	var p [66]byte
	priv := pk.priv.D.FillBytes(p[:])
	priv = priv[66-(pk.priv.Curve.Params().BitSize+7)/8:]

	return "k2:" + base64.RawURLEncoding.EncodeToString(priv)
}

var (
	oidPublicKeyEdDSA = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

type publicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func ed25519Identity(pub ed25519.PublicKey) (Identity, error) {
	b, err := asn1.Marshal(publicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyEdDSA,
		},
		PublicKey: asn1.BitString{BitLength: len(pub) * 8, Bytes: pub},
	})
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		hash: sha256.Sum256(b),
	}, nil
}

func ecdsaIdentity(key *ecdsa.PrivateKey) (Identity, error) {
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		// We generate the private/public key pair. Hence, (X,Y)
		// should always be a point on the elliptic curve.
		// However, we want to be really sure to not accidentally
		// compute an invalid identity.
		return Identity{}, errors.New("mtls: invalid ECDSA public key for curve")
	}

	var curveID asn1.ObjectIdentifier
	switch key.Curve {
	default:
		return Identity{}, errors.New("mtls: curve " + key.Curve.Params().Name + " is not supported")
	case elliptic.P256():
		curveID = oidNamedCurveP256
	case elliptic.P384():
		curveID = oidNamedCurveP384
	case elliptic.P521():
		curveID = oidNamedCurveP521
	}
	params, err := asn1.Marshal(curveID)
	if err != nil {
		return Identity{}, err
	}

	pubKey := elliptic.Marshal(key.Curve, key.X, key.Y)
	b, err := asn1.Marshal(publicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyECDSA,
			Parameters: asn1.RawValue{FullBytes: params},
		},
		PublicKey: asn1.BitString{BitLength: len(pubKey) * 8, Bytes: pubKey},
	})
	if err != nil {
		return Identity{}, err
	}

	return Identity{
		hash: sha256.Sum256(b),
	}, nil
}

// NewCertificate returns a new TLS certificate using the
// given private key.
func newCertificate(key PrivateKey) (*tls.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: key.Identity().String(),
		},
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Now().UTC().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key.Private())
	if err != nil {
		return nil, err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key.Private())
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
	)
	if err != nil {
		return nil, err
	}
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, err
		}
	}
	return &cert, nil
}
