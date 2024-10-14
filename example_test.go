// Copyright (c) 2024 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package mtls_test

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"aead.dev/mtls"
)

// ExampleClient shows how to configure a simple HTTP client verifying
// a pinned public key for the server running at "10.1.2.3:443". For all
// other servers it uses regular TLS certificate verification. The client
// does not authenticate itself to the server.
//
// Hence, the server running at "10.1.2.3:443" does not have to have a
// certificate issued by a CA trusted by the client.
func ExampleClient() {
	// The server's identity - required to verify mTLS handshakes with the server.
	const Identity = "h1:dKNb3WhlZ1dxE6VSI1mH7FAd2EPTijEU37RHvkhuT7Y"

	srvIdentity, err := mtls.ParseIdentity(Identity)
	if err != nil {
		log.Fatalf("failed to parse identity: %v", err)
	}

	clientConf := mtls.Client{
		// Map a set of server addresses to identites. The client expects
		// that the server with address X has a public identity Y.
		PeerIdentities: map[string]mtls.Identity{
			"10.1.2.3:443": srvIdentity,
		},
		GetPeerIdentity: nil, // If the mapping isn't static, consider this callback instead

		// Optionally, configure mTLS connections, like minimal supported
		// version or HTTP/2 support.
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},

		// Optionally, provide a custom net.Dialer to customize network timeouts, keepalives, etc.
		Dialer: net.Dialer{
			Timeout: 10 * time.Second,
		},

		// Optionally, if the client should also verify certificates from other TLS servers,
		// e.g. some external systems that serve regular certificates issued by trusted CAs,
		// provide the regular TLS client config here.
		Config: &tls.Config{
			RootCAs: nil, // The set of root CA certificates the client trusts.
		},
	}
	client := http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialTLSContext:        clientConf.DialTLSContext, // Use the mTLS config
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	_ = client

	// Output:
}

// ExampleClient_PrivateKey shows how to configure a simple HTTP client verifying
// a pinned public key for all servers running at "*.my-service.example.com". The
// client authenticates itself using its private/public key pair when connecting to
// these servers. For all other servers it uses regular TLS certificate verification
// and does not authenticate itself.
//
// Hence, the server running at "*.my-service.example.com" don't not have to have a
// certificate issued by a CA trusted by the client.
func ExampleClient_PrivateKey() {
	// The server's identity - required to verify mTLS handshakes at the client.
	const Identity = "h1:5OEhsTTKZiK-IFE-Fi6W-VWwp_YLbxik0wxQBNc0_6s"

	srvIdentity, err := mtls.ParseIdentity(Identity)
	if err != nil {
		log.Fatalf("failed to parse identity: %v", err)
	}

	// The client's private key - used to authenticate to the server during mTLS handshakes.
	// The server must know the identity of the client's private key to be able to verify
	// the client.
	const PrivateKey = "k2:q-sFRxPrJNevr8cztwnMONKtC5eVC3an42AWijBGOtc"

	clientKey, err := mtls.ParsePrivateKey(PrivateKey)
	if err != nil {
		log.Fatalf("failed to parse identity: %v", err)
	}

	clientConf := mtls.Client{
		PrivateKey: clientKey, // Authenticate to mTLS servers using this private/public key pair

		// Map a set of server addresses to identites. The client expects
		// that the server with address X has a public identity Y.
		PeerIdentities: nil,

		// Use the GetPeerIdentity callback to determine which servers require mTLS authentication
		// and which identity corresponds to which server. Here, there is just one identity for all
		// servers.
		GetPeerIdentity: func(addr string) (mtls.Identity, bool) {
			if host, _, err := net.SplitHostPort(addr); err == nil {
				if strings.HasSuffix(host, ".my-service.example.com") { // Matches e.g. srv-1.my-service.example.com
					return srvIdentity, true
				}
			}
			return mtls.Identity{}, false
		},

		// Optionally, configure mTLS connections, like minimal supported
		// version or HTTP/2 support.
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},

		// Optionally, provide a custom net.Dialer to customize network timeouts, keepalives, etc.
		Dialer: net.Dialer{
			Timeout: 10 * time.Second,
		},

		// Optionally, if the client should also verify certificates from other TLS servers,
		// e.g. some external systems that serve regular certificates issued by trusted CAs,
		// provide the regular TLS client config here.
		Config: &tls.Config{
			RootCAs: nil, // The set of root CA certificates the client trusts.
		},
	}
	client := http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialTLSContext:        clientConf.DialTLSContext, // Use the mTLS config
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	_ = client

	// Output:
}

// ExampleServer shows how to configure a simple HTTP server that
// serves a certificate with a pinned public key. All clients that
// know the server's identity are able to verify the server.
//
// The server does not authenticate clients.
func ExampleServer() {
	const PrivateKey = "k2:IqYLb-5B3YvUR28WcJoGo3zhWa5GnrcJ9knLEWCHsRU"

	priv, err := mtls.ParsePrivateKey(PrivateKey)
	if err != nil {
		log.Fatalf("failed to parse private key: %v", err)
	}

	srvConf := mtls.Server{
		PrivateKey: priv, // Use the private key for mTLS connections

		// Optionally, configure mTLS connections, like minimal supported
		// version or HTTP/2 support.
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},

		// Optionally, require and verify client public keys. Provide either
		// a static list of client identities or a callback to verify the
		// peer identity of an incoming mTLS connection.
		PeerIdentities:     []mtls.Identity{},
		VerifyPeerIdentity: func(peer mtls.Identity) error { return nil },

		// Optionally, set a public-facing TLS config for regular (e.g. non-mTLS) clients.
		Config: &tls.Config{
			Certificates:   nil, // Provide your public-facing certificates here
			GetCertificate: nil, // or here, if any
		},
	}
	_ = http.Server{
		Addr: ":443",
		TLSConfig: &tls.Config{
			GetConfigForClient: srvConf.GetConfigForClient,
		},
	}
	// Output:
}

// ExampleServer shows how to configure a simple HTTP server that
// serves a certificate with a pinned public key. All clients that
// know the server's identity are able to verify the server.
//
// The server verifies clients using the VerifyPeerIdentity callback.
func ExampleServer_VerifyPeerIdentity() {
	const PrivateKey = "k2:nJev7FTHw5Up-Hbev_iQ-ukYZtDbceXowrhUFcF9zd8"

	priv, err := mtls.ParsePrivateKey(PrivateKey)
	if err != nil {
		log.Fatalf("failed to parse private key: %v", err)
	}

	// The client's identity - required to verify mTLS handshakes at the server.
	const Identity = "h1:6mn2_7XHfySVJYH0JN5R0kYZjr8I7q4j34BogumV3tM"

	clientIdentity, err := mtls.ParseIdentity(Identity)
	if err != nil {
		log.Fatalf("failed to parse identity: %v", err)
	}

	srvConf := mtls.Server{
		PrivateKey: priv, // Use the private key for mTLS connections

		// Verify the public key's identity of an incoming mTLS connection
		VerifyPeerIdentity: func(peer mtls.Identity) error {
			if peer == clientIdentity {
				return nil
			}
			return errors.New("unknown peer identity: access denied")
		},

		// Optionally, configure mTLS connections, like minimal supported
		// version or HTTP/2 support.
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},

		// Optionally, set a public-facing TLS config for regular (e.g. non-mTLS) clients.
		Config: &tls.Config{
			Certificates:   nil, // Provide your public-facing certificates here
			GetCertificate: nil, // or here, if any
		},
	}
	_ = http.Server{
		Addr: ":443",
		TLSConfig: &tls.Config{
			GetConfigForClient: srvConf.GetConfigForClient,
		},
	}
	// Output:
}

// ExampleClientServer shows how to send a GET request from a client to server
// over a mTLS connection. The client and server verify the identity of their
// peers.
func ExampleClientServer() {
	// The client and server private key. Private keys should never be exposed!
	const (
		ServerPrivateKey = "k2:RsxEXi8ebLIWI8BI9MJHGBqKa1keq67Ds8hrgetZV1M" // Only known to the server
		ClientPrivateKey = "k2:RtSJhCLcHMAcMlIynDayappxUNl0iSQtggHKNCUXrdQ" // Only known to the client
	)

	serverKey, err := mtls.ParsePrivateKey(ServerPrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	clientKey, err := mtls.ParsePrivateKey(ClientPrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	// The public key identites to the corresponding private keys.
	// Identities aren't secrets and you have to have the identity
	// of your connection peer to authenticate and verify the connection.
	var (
		ServerIdentity = serverKey.Identity() // This must be known by the client to verify the server
		ClientIdentity = clientKey.Identity() // This must be known by the server to verify the client
	)

	// Create a simple HTTPS server that computes the peer identity from the TLS handshake information
	// and responds with: "Hello <IDENTITY>"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := mtls.PeerIdentity(r.TLS)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Write([]byte("Hello " + id.String()))
	}))

	// Configure and start the HTTPS server.
	server.TLS = &tls.Config{
		GetConfigForClient: (&mtls.Server{
			PrivateKey:     serverKey,
			PeerIdentities: []mtls.Identity{ClientIdentity},
		}).GetConfigForClient,
	}
	server.StartTLS()

	// Create a new client that authenticates to the HTTPS server with its private/public key pair.
	// Note that this a new client, not server.Client(), that does not trust the server certificate
	// generated by the httptest.Server automatically.
	client := http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialTLSContext: (&mtls.Client{
				PrivateKey:      clientKey, // Set a private key to auth. to the server
				GetPeerIdentity: func(string) (mtls.Identity, bool) { return ServerIdentity, true },
				Dialer:          net.Dialer{Timeout: 10 * time.Second},
			}).DialTLSContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	// Send a simple GET request to the server and print the response to stdout.
	// Here, the client verifies the server's identity and the server verifies the
	// client's identity. Hence, mutual TLS authentication.
	resp, err := client.Get(server.URL)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	var buf strings.Builder
	if _, err := io.Copy(&buf, resp.Body); err != nil {
		log.Fatal(err)
	}
	fmt.Println(buf.String())
	// Output: Hello h1:OyfAzRVITGK2QUjHrYg0IC7y5hVjt93FZVucAgSuPeE
}
