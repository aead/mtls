// Copyright (c) 2024 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package mtls

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
)

// A Client structure is used to configure a mTLS client.
//
// It establishes a mTLS connection for any server within
// PeerIdentities or for which GetPeerIdentity returns true.
// Without a private key, a client does not authenticate
// itself to the mTLS server(s).
//
// Once a client has been passed to a TLS function, it must
// no longer be modified.
type Client struct {
	// PrivateKey is the private key used to authenticate
	// to the mTLS server by sending the corresponding
	// public key during the TLS handshake. If not set,
	// then the client does not authenticate itself.
	//
	// The server has to know the corresponding public key
	// identity to verify the client.
	PrivateKey PrivateKey

	// PeerIdentities contains a static mapping from network
	// addresses to identities. When establishing a connection
	// to one of the addresses, the client performs a mTLS handshake
	// expecting a public key that matches the identity assigned
	// to the address.
	//
	// For mapping identities to network address dynamicially set
	// GetPeerIdentity.
	PeerIdentities map[string]Identity

	// GetPeerIdentity is called whenever the client establishes a
	// network connection. The addr is the server's network address
	// as passed to [crypto/tls.Dial] - usually host:port. If it returns
	// true, the client performs a mTLS handshake expecting a public key
	// that matches the returned identity.
	GetPeerIdentity func(addr string) (Identity, bool)

	// Config is the TLS config used when connecting to other TLS servers
	// not within PeerIdentities or for which GetPeerIdentity returns false.
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

	// Dialer contains options for connecting to a network address.
	Dialer net.Dialer

	once   sync.Once
	config *tls.Config
}

// DialContext connects to the given network address and initiates a TLS
// handshake, returning the resulting TLS connection.
//
// The provided Context must be non-nil. If the context expires before
// the connection is complete, an error is returned. Once successfully
// connected, any expiration of the context will not affect the
// connection.
//
// The returned Conn, if any, will always be of type *crypto/tls.Conn.
func (c *Client) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c.once.Do(func() {
		c.config = &tls.Config{
			MinVersion:   c.MinVersion,
			MaxVersion:   c.MaxVersion,
			NextProtos:   c.NextProtos,
			CipherSuites: c.CipherSuites,

			// We verify mTLS connections using VerifyConnection.
			// Regular TLS connections are verified using Client.Config.
			InsecureSkipVerify: true,
			VerifyConnection: func(state tls.ConnectionState) error {
				if state.DidResume {
					return nil
				}

				// We set the SNI to the public key identity that we expect
				// when making a network connection. So state.ServerName is
				// NOT coming from the server but is the result of either:
				//  - PeerIdentities
				//  - GetPeerIdentity
				id, err := ParseIdentity(state.ServerName)
				if err != nil {
					return err
				}

				peer, err := PeerIdentity(&state)
				if err != nil {
					return &tls.CertificateVerificationError{
						UnverifiedCertificates: state.PeerCertificates,
						Err:                    err,
					}
				}

				// Now, verify that the server's public key actually matches
				// the expected, and requested, identity. If it does, the
				// TLS handshake guarantees that the server holds the corresponding
				// private key. If the server would not know the private key for
				// the public key it sends, the TLS handshake would have aborted
				// already.
				if id != peer {
					return &tls.CertificateVerificationError{
						UnverifiedCertificates: state.PeerCertificates,
						Err: IdentityError{
							Identity:     id,
							PeerIdentity: peer,
						},
					}
				}
				return nil
			},
		}

		// If we have a private key, send the corresponding public key to the server
		// if it requests a client certificate.
		if c.PrivateKey != nil {
			cert, err := newCertificate(c.PrivateKey)
			c.config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, err }
		}
	})

	var (
		id Identity
		ok bool
	)
	if c.GetPeerIdentity != nil {
		id, ok = c.GetPeerIdentity(addr)
	}
	if !ok && len(c.PeerIdentities) > 0 {
		id, ok = c.PeerIdentities[addr]
	}

	dialer := tls.Dialer{
		NetDialer: &c.Dialer,
	}
	if ok {
		dialer.Config = c.config.Clone() // Clone because we modify the SNI
		dialer.Config.ServerName = id.String()
	} else {
		dialer.Config = c.Config
	}
	return dialer.DialContext(ctx, network, addr)
}
