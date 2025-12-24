[![Go Reference](https://pkg.go.dev/badge/aead.dev/mtls.svg)](https://pkg.go.dev/aead.dev/mtls)

# [m]TLS

A Go library for TLS/HTTPS using public key pinning instead of certificate authorities.

**The Problem**

Usually TLS/HTTPS relies on certificate authorities (CAs) to establish trust. This means:
- Obtaining and renewing certificates from CAs
- Managing certificate chains and trust stores
- Trusting any certificate signed by a trusted CA

For services that communicate with known peers this is overkill.

**The Solution**

This library takes an SSH-like approach to TLS authentication. Just like SSH's `known_hosts` file lets you trust
specific server keys directly, `mtls` lets you identify peers by their public key hash rather than CA signatures.

```
h1:2eYrKRe4K9Xf_HjOhdJjNPuH5P8sLN9XNgdgZKfqt1A
```

That's it. No certificates to issue, no chains to verify, no CAs to manage.

## How It Works

First, let's take a look at a client connecting to an HTTPS server and verifying its public key:

<details>

<summary><b>Show Example Code</b></summary>

```go
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"aead.dev/mtls"
)

// In this example, we configure, start and establish a
// secure TLS connection to a HTTPS server without
// configuring certificates or CAs.
func main() {
	// The server's private key
	const PrivateKey = "k1:xZnpcYtPdVMNLBBRaUO5HPEoK_jVrcc3MWR8BshkjJw"

	privKey, err := mtls.ParsePrivateKey(PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	// Our 'Hello World' server using a minimal TLS configuration.
	srv := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("Hello from server [ identity=%s ]\n", r.TLS.ServerName)
		}),

		TLSConfig: &tls.Config{
			GetConfigForClient: (&mtls.Server{
				PrivateKey: privKey,
			}).GetConfigForClient,
		},
	}

	// Our client needs to know the server's identity in order
	// to verify the public key presented by the server during
	// TLS handshakes.
	identity := privKey.Identity()
	client := http.Client{
		Transport: &http.Transport{
			DialTLSContext: (&mtls.Client{
				// Here we define which identity to expect when connecting
				// to a server.
				GetPeerIdentity: func(_ string) (mtls.Identity, bool) {
					return identity, true
				},
			}).DialTLSContext,
		},
	}

	// Listen on port 4443 and start the HTTPS server.
	listener, err := net.Listen("tcp", "0.0.0.0:4443")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	go func() { log.Print(srv.ServeTLS(listener, "", "")) }()

	// Connect to our server, perform a TLS handshake,
	// verify that the server's public key corresponds
	// to the expected identity and print the response
	// to the terminal.
	resp, err := client.Get("https://127.0.0.1:4443")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// At this point we have established a secure TLS
	// connection without configuring certificates or
	// CAs.
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		log.Fatal(err)
	}
}
```
</details>

[This example](https://go.dev/play/p/0bLM3BfSvu-) produces the following output:
```
Hello from server [ identity=h1:l4AoVm6xKAVGsfo8J_ttCOC6Odgq3GJLHg5NtAdOAr0 ]
```

Instead of verifying that the server presents a certificate issued by a trusted CA, the client
verifies that the server presents a public key matching an expected identity (SHA-256 hash).
However, the client does not authenticate itself to the server.

We can modify our initial example as following to mutually authenticate during the TLS handshake:

<details>

<summary><b>Show Example Code</b></summary>

```go
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"aead.dev/mtls"
)

// In this example, we configure, start and establish a
// secure mutual TLS connection to a HTTPS server without
// configuring certificates or CAs.
func main() {
	const PrivateKeyServer = "k1:xZnpcYtPdVMNLBBRaUO5HPEoK_jVrcc3MWR8BshkjJw"
	const PrivateKeyClient = "k1:uNTwsVpygybzFuHPYE04Luw2te-D2Efr5xnxycGpt4c"

	srvKey, err := mtls.ParsePrivateKey(PrivateKeyServer)
	if err != nil {
		log.Fatal(err)
	}
	clientKey, err := mtls.ParsePrivateKey(PrivateKeyClient)
	if err != nil {
		log.Fatal(err)
	}

	srvIdentity := srvKey.Identity()
	clientIdentity := clientKey.Identity()

	// Our 'Hello World' server using a minimal TLS configuration.
	// Our server needs to know the client's identity in order to
	// verify the public key presented by the client during TLS
	// handshakes.
	srv := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("Hello from server [ identity=%s ] \n      to   client [ identity=%s ]\n",
				r.TLS.ServerName,
				mtls.CertificateIdentity(r.TLS.PeerCertificates[0]),
			)
		}),

		TLSConfig: &tls.Config{
			GetConfigForClient: (&mtls.Server{
				PrivateKey:     srvKey,
				PeerIdentities: []mtls.Identity{clientIdentity},
			}).GetConfigForClient,
		},
	}

	// Our client needs to know the server's identity in order
	// to verify the public key presented by the server during
	// TLS handshakes.
	client := http.Client{
		Transport: &http.Transport{
			DialTLSContext: (&mtls.Client{
				PrivateKey: clientKey,
				// Here we define which identity to expect when connecting
				// to a server.
				GetPeerIdentity: func(_ string) (mtls.Identity, bool) {
					return srvIdentity, true
				},
			}).DialTLSContext,
		},
	}

	// Listen on port 4443 and start the HTTPS server.
	listener, err := net.Listen("tcp", "0.0.0.0:4443")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	go func() { log.Print(srv.ServeTLS(listener, "", "")) }()

	// Connect to our server, perform a TLS handshake,
	// verify that the server's public key corresponds
	// to the expected identity and print the response
	// to the terminal.
	resp, err := client.Get("https://127.0.0.1:4443")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// At this point we have established a secure TLS
	// connection without configuring certificates or
	// CAs.
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		log.Fatal(err)
	}
}
```
</details>

[This example](https://go.dev/play/p/g8uqCWppDkc) produces the following output:
```
Hello from server [ identity=h1:l4AoVm6xKAVGsfo8J_ttCOC6Odgq3GJLHg5NtAdOAr0 ] 
      to   client [ identity=h1:z5PgEqVUH_gwBt7oNKX9p9tchzL0i98U6O9C_aM4Y-k ]
```

Now, the server verifies that the public key presented by the client matches the
expected client identity and the client verifies that the public key presented
by the server matches the expected server identity.

## Getting Started

```sh
go get aead.dev/mtls@latest
```

This downloads the `mtls` module. It has no dependencies.

Add the `aead.dev/mtls` module to your `go.mod` file.
The documentation contains [examples](https://pkg.go.dev/aead.dev/mtls#example-package) on how to configure clients and servers.
