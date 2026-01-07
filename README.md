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

## FAQs

<details>
<summary>How can TLS without CA-signed certificates be secure?</summary>

**TL;DR: Because peers get to know others public keys out-of-band and don't have to rely on a trusted third party for this.**

A certificate is a cryptographically signed statement claiming that some public key `P` is associated with a named entity.
For example, public key of `example.com` is `P`. 

When a CA issues a certificate it verifies that whoever requests the certficate:
 - has the private key that corresponds to the public key in the certificate.
 - and controlls or is responsible for the name(s) in the certificate.

If you want get a CA-issued certificate for `example.com` with the public key `P` then you have to proof to
the CA that you have the corresponding private key and that you are currently controlling the `example.com` domain.

Basically, all a CA is doing is creating (temporal) cryptographically signed statements about which public key
belongs to which entity. However, if we know the public keys of our peers beforehand, we don't need a thrid party
telling us.

In fact, pinning our peer's public key is strictly more secure than relying on CA-issued certificates because
we no longer have to trust that the CA only ever issues "correct" certificates. A CA becoming malicious or getting
compromised is no longer a risk in our threat model.
</details>

<details>
<summary>When do I need to renew/change my keys?</summary>
  
**TL;DR: You don't have to. You can change them whenever you like and you should change them if they could be compromised.**

Certificates expire and have to be renewed mainly because a certificate is a cryptographically signed
statement associating a public key with named entities. For example, the public key of `example.com`
is `P`.

Such statements are (ideally) true at some point in time but may not be forever. For example,
the ownership of the `example.com` domain may change or the corresponding private key gets lost or
compromised. A certificates can be revoked explicitly but the fact that it got revoked has to be
recorded and distributed to everyone until it actually expires. If certificates didn’t expire, this
information would need to be recorded forever.

Certificate renewal is primarily not about changing the key pair. It's perfectly fine to reuse the same
key pair when renewing a certificate. However, most implementations generate a new key pair, as key
generation is cheap.

With public key pinning, there’s no third party issuing signed statements that could expire or become invalid,
so there’s nothing to renew. While key pairs can be changed, this can be done at any time by updating all peers
that rely on the key pair or public key hash—such as through a configuration update.

If a private key is potentially compromised, it should be replaced, regardless of whether certificates or public 
key pinning is being used.
</details>

<details>
<summary>Can I use both, CA-issued certificates and public key pinning, at the same time?</summary>
  
**TL;DR: Yes. For example with a separate `tls.Config` at the [client](https://pkg.go.dev/aead.dev/mtls#Client.Config) and [server](https://pkg.go.dev/aead.dev/mtls#Server.Config)**

During the TLS handshake, the TLS client can indicate to which server it's trying to connect to via
the server name indication ([SNI](https://www.rfc-editor.org/rfc/rfc3546#section-3.1)) extension.
A TLS server may be responsible for multiple domains. For example, `foo.com` as well as `bar.com`.
A client trying to connect to this server has to include the domain name in the SNI such that the
server knows whether it should present the certificate issued for `foo.com` or the one for `bar.com`.

This mechanism can also be used to distingush between handshakes expecting a certificate issued for some
domain(s) and handshakes expecting a particular public key. 

```go
http.Server{
    TLSConfig: &tls.Config{
        GetConfigForClient: (&mtls.Server{
            // The server's private key used. Clients need to know the corresponding
            // public key hash.
            PrivateKey: privKey,

            // Alternative TLS configuration used when clients don't provide a SNI matching the
            // server's public key hash.
            Config: &tls.Config{
                GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
                    // TODO: Return the certificiate matching the client hello.
                },
            },
        }).GetConfigForClient,
    },
}
```

With such a configuration, the server behaves like a "regular" TLS/HTTPS server serving signed certificates
issued for domains unless a client specifically asks for the public key corresponding the server's `PrivateKey`.

Similarly, a client can only use key pinning for specific servers:

```go
client := http.Client{
    Transport: &http.Transport{
        DialTLSContext: (&mtls.Client{
            // We only expect a particular public key (matching srvIdentity) if
            // we are connecting to the DB server. Otherwise, we use "regular"
            // X.509 certificate verification. See Config below.
            GetPeerIdentity: func(addr string) (mtls.Identity, bool) {
                if addr == DBServer {
                    return srvIdentity, true
                }
                return mtls.Identity{}, false
            },

            // The TLS config used for other TLS handshakes.
            Config: &tls.Config{},
        }).DialTLSContext,
    },
}
```

Under the hood, the client sends the public key hash as SNI whenever it expects a particular public key
from the server and the server only response with its public key when it receives a SNI containing its
public key hash. For example:
```
SNI=h1:l4AoVm6xKAVGsfo8J_ttCOC6Odgq3GJLHg5NtAdOAr0
```

This has the nice property that clients cannot detect whether a server would serve a different public key
unless they know the hash of the public key. For such clients, the server behaves like any other TLS server.
</details>

## Getting Started

```sh
go get aead.dev/mtls@latest
```

This downloads the `mtls` module. It has no dependencies.

Add the `aead.dev/mtls` module to your `go.mod` file.
The documentation contains [examples](https://pkg.go.dev/aead.dev/mtls#example-package) on how to configure clients and servers.
