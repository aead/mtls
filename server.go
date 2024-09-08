// Copyright (c) 2024 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package mtls

import (
	"crypto/tls"
	"slices"
	"sync"
)

// A Server structure is used to configure a mTLS server.
type Server struct {
	// PrivateKey is the server's private key used to authenticate
	// to mTLS clients by sending the corresponding public key during
	// the TLS handshake. If not set, the server will use Config for
	// all incoming TLS connections.
	//
	// Clients that try to establish a mTLS connection should send
	// the PrivateKey's public key identity as server name (SNI).
	//
	// Clients have to know the corresponding public key identity to
	// verify the client.
	PrivateKey PrivateKey

	// PeerIdentities contains a static list of accepted peers. If set,
	// the server only accepts an incoming TLS connection from peers
	// that present one of the listed public keys during the TLS handshake.
	//
	// The server requests a certificate from the clinet only if PeerIdentities
	// is not nil, or VerifyPeerIdentity is set.
	PeerIdentities []Identity

	// VerifyPeerIdentity verifies the connection peer's identity during
	// the TLS handshake. If it returns an error, the handshake is aborted.
	//
	// The server requests a certificate from the clinet only if PeerIdentities
	// is not nil, or VerifyPeerIdentity is set.
	VerifyPeerIdentity func(Identity) error

	// Config is the TLS config used for regular TLS clients that don't send
	// the PrivateKey's public key identity as SNI.
	Config *tls.Config

	// MinVersion contains the minimum TLS version that is acceptable for
	// mTLS connections. For specifying the minimum TLS versions for regular
	// TLS connections use Config.MinVersion.
	//
	// By default, TLS 1.2 is currently used as the minimum. TLS 1.0 is the
	// minimum supported by this package.
	MinVersion uint16

	// MaxVersion contains the maximum TLS version that is acceptable for
	// mTLS connections. For specifying the maximum TLS versions for regular
	// TLS connections use Config.MaxVersion.
	MaxVersion uint16

	// NextProtos is a list of supported application level protocols for mTLS
	// connections, in order of preference. If both peers support ALPN, the
	// selected protocol will be one from this list, and the connection will
	// fail if there is no mutually supported protocol. If NextProtos is empty
	// or the peer doesn't support ALPN, the connection will succeed and
	// ConnectionState.NegotiatedProtocol will be empty.
	//
	// For specifying the supported application level protocols for regular
	// TLS connections use Config.NexProtos.
	NextProtos []string

	// CipherSuites is a list of enabled TLS 1.0–1.2 cipher suites for mTLS
	// connections. The order of the list is ignored. Note that TLS 1.3
	// ciphersuites are not configurable.
	//
	// If CipherSuites is nil, a safe default list is used. The default cipher
	// suites might change over time.
	//
	// For specifying the enabled TLS 1.0-1.2 cipher suites for regular
	// TLS connections use Config.CipherSuites.
	CipherSuites []uint16

	once         sync.Once
	privIdentity string // Pre-computed identity of PrivateKey's public key
	config       *tls.Config
}

// GetConfigForClient returns a TLS config for a TLS client hello message.
//
// It returns a configuration for mutual TLS when a private key is set and
// the client sends the corresponding public key identity via SNI. Otherwise,
// it returns Server.Config.
func (s *Server) GetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	s.once.Do(func() {
		if s.PrivateKey == nil {
			// Don't set a mTLS config. Instead use the regular TLS Config for
			// all connections.
			return
		}

		s.privIdentity = s.PrivateKey.Identity().String()
		cert, err := newCertificate(s.PrivateKey)

		s.config = &tls.Config{
			MinVersion:   s.MinVersion,
			MaxVersion:   s.MaxVersion,
			NextProtos:   s.NextProtos,
			CipherSuites: s.CipherSuites,

			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, err },
			VerifyConnection: func(state tls.ConnectionState) error {
				if state.DidResume {
					return nil
				}

				if s.VerifyPeerIdentity != nil || len(s.PeerIdentities) > 0 {
					peer, err := PeerIdentity(&state)
					if err != nil {
						return &tls.CertificateVerificationError{
							UnverifiedCertificates: state.PeerCertificates,
							Err:                    err,
						}
					}

					if s.VerifyPeerIdentity != nil {
						if err = s.VerifyPeerIdentity(peer); err != nil {
							return &tls.CertificateVerificationError{
								UnverifiedCertificates: state.PeerCertificates,
								Err:                    err,
							}
						}
					} else {
						if !slices.Contains(s.PeerIdentities, peer) {
							return &tls.CertificateVerificationError{
								UnverifiedCertificates: state.PeerCertificates,
								Err:                    IdentityError{PeerIdentity: peer},
							}
						}
					}
				}
				return nil
			},
		}
		if s.VerifyPeerIdentity != nil || len(s.PeerIdentities) > 0 {
			s.config.ClientAuth = tls.RequestClientCert
		}
	})

	if s.PrivateKey != nil && hello.ServerName == s.privIdentity {
		return s.config, nil
	}
	return s.Config, nil
}
