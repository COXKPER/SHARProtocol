# SHARProtocol (Go Implementation)

[![Go Reference](https://pkg.go.dev/badge/github.com/COXKPER/SHARProtocol.svg)](https://pkg.go.dev/github.com/COXKPER/SHARProtocol)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)](LICENSE)

Go implementation of **SHARP** (**S**elf-**H**osted **A**ddress **R**outing **P**rotocol) - a decentralized email protocol and client specification from [twoblade](https://github.com/outpoot/twoblade) using the `#` symbol for addressing (e.g. `user#domain.com`).

---

## Protocol Overview (SHARP/1.4)

- **Addressing:** `user#domain.com` (optionally `user#domain.com:port`).
- **Transport:** Line-delimited JSON over TCP.
- **Default Ports:** 5000 (SHARP TCP protocol), 5001 (HTTP API).
- **Discovery:** DNS SRV record `_sharp._tcp.<domain>` falling back to `sharp.<domain>:5000`.
- **Anti-Spam:** Hashcash Proof-of-Work (5 trivial, 10 weak, 18 recommended).

### Versions

| Version | Anti-spam digest | Notes |
|---|---|---|
| `SHARP/1.3` | SHA-1 | Still fully supported. |
| `SHARP/1.4` | SHA-256 | Adds optional signatures, message ids and version negotiation. |

`ProtocolVersion` is `SHARP/1.4`. A 1.4 peer and a 1.3 peer interoperate in both
directions without configuration; see [Backward compatibility](#backward-compatibility).

### Message Exchange Flow

```
Client                                  Server
  |                                       |
  | --- HELLO (server_id, supported, ---> |
  |      capabilities)                    |
  | <-- OK (agreed version, caps) ------- |
  |                                       |
  | --- MAIL_TO (+ hashcash, -----------> |
  |      message_id, signature)           |
  | <-- OK -------------------------------|
  |                                       |
  | --- DATA ---------------------------> |
  | <-- OK -------------------------------|
  |                                       |
  | --- EMAIL_CONTENT ------------------> |
  | <-- OK (Received) ------------------- |
  |                                       |
  | --- END_DATA -----------------------> |
  | <-- OK (Processed) ------------------ |
```

### What 1.4 Adds

Everything below is optional and negotiated per session. A peer that does not
advertise a capability never receives the extension, so nothing here can break a
1.3 correspondent.

1. **Version negotiation.** `HELLO` carries `supported`, the full version list.
   The server replies with the newest shared version. A 1.3 peer sends only its
   single `protocol` string and is understood anyway. The client offers 1.4
   first and transparently retries at 1.3 if the peer rejects it.
2. **Capabilities.** `HELLO` and its reply carry a `capabilities` list:
   `signatures`, `hashcash-sha256`, `message-id`.
3. **Detached signatures.** The sender attaches a base64 Ed25519 `public_key`
   and a `signature` covering `from`, `to`, `message_id`, subject, body, content
   type, HTML body and attachments. Each field is length-prefixed, so text
   cannot be shifted between fields without invalidating the signature.
4. **Trust on first use.** `TrustStore` pins the first key seen for an address.
   A later, different key is reported as `SignatureUntrustedKey` and the mail is
   refused rather than quietly accepted.
5. **Message ids and duplicate suppression.** A sender-assigned `message_id`
   lets a receiver collapse a retry into one delivery.
6. **SHA-256 hashcash.** Version 2 tokens. Version 1 (SHA-1) tokens are still
   minted on request and still verified, because every 1.3 peer sends them.

### What a Signature Does and Does Not Prove

Worth stating plainly, because the distinction is easy to overstate:

- It **does** prove that the holder of the private key produced the message, and
  that no field was altered in transit.
- It does **not** prove the key belongs to the person named in `from`. Binding a
  key to an address is what a `TrustStore` adds, and only after the first
  message from that address has been accepted.
- There is no certificate authority and no third party to trust. If a
  correspondent genuinely rotates their key, an operator confirms it out of band
  and calls `Forget` to re-pin.
- A 1.3 peer sends no signature at all. `Email.Signed()` reports whether
  material is present; the verification verdict comes from the server's
  `OnSignature` callback.

---

## Installation

```bash
go get github.com/COXKPER/SHARProtocol@latest
```

---

## Quick Start

### 1. Running a SHARP Server

A server that speaks 1.4 but applies no 1.4 policy still serves 1.3 peers
exactly as before.

```go
package main

import (
	"fmt"
	"log"

	"github.com/COXKPER/SHARProtocol"
)

func main() {
	server := twoblade.NewServer("example.com", 5000, func(username, domain string) bool {
		return username == "alice"
	}, func(email twoblade.Email) error {
		fmt.Printf("Received email from %s (%s, %s): %s\n",
			email.From, email.Version(), email.SignatureStatus(), email.Subject)
		return nil
	})

	// Optional: verify signatures and pin sender keys on first use.
	store, err := twoblade.NewTrustStore("trust.json")
	if err != nil {
		log.Fatal(err)
	}
	server.TrustStore = store

	// Optional: drop a retry that reuses a message id.
	server.DedupeMessageID = true

	// Optional, and deliberately off: rejecting unsigned mail also rejects
	// every 1.3 sender.
	// server.RequireSignature = true

	log.Fatal(server.Start())
}
```

### 2. Sending an Email

```go
package main

import (
	"log"

	"github.com/COXKPER/SHARProtocol"
)

func main() {
	to := "alice#example.com:5000"
	token, err := twoblade.GenerateHashcash(to, 10)
	if err != nil {
		log.Fatal(err)
	}

	client := twoblade.NewClient()
	err = client.Send("127.0.0.1:5000", twoblade.Email{
		From:        "bob#sender.com",
		To:          to,
		Subject:     "Hello from Go!",
		Body:        "This email is delivered over SHARP.",
		ContentType: "text/plain",
		Hashcash:    token,
	})
	if err != nil {
		log.Fatal(err)
	}
}
```

### 3. Sending Signed Mail

A signing client still delivers to a 1.3 peer, unsigned, unless you ask it not to.

```go
key, err := twoblade.GenerateSigningKey("bob#sender.com")
if err != nil {
	log.Fatal(err)
}
log.Println("my key fingerprint:", twoblade.Fingerprint(key.PublicKey))

client := twoblade.NewClient()
client.SigningKey = key
// Log when a 1.4 feature is dropped for a peer that cannot use it.
client.OnDegrade = func(reason string) { log.Println("degraded:", reason) }
// Set RequireSignatures to fail instead of sending unsigned mail.
```

### 4. Running the Standalone Daemon

```bash
go run ./cmd/sharpd -domain example.com -port 5000
go run ./cmd/sharpd -domain example.com -trust-store trust.json
```

---

## Backward compatibility

The 1.4 additions are additive by construction, and the test suite enforces it:

- A 1.3-shaped client (`interop_13_test.go` re-implements the v1.0.1 wire
  structs verbatim) delivers to a 1.4 server unmodified.
- A 1.4 client delivers to a server that rejects anything but `SHARP/1.3`.
- SHA-1 hashcash tokens still verify; SHA-256 tokens verify alongside them.
- Servers that never set `TrustStore`, `RequireSignature`, `DedupeMessageID` or
  `OnSignature` behave exactly as they did on 1.3.

Unknown JSON keys are ignored by `encoding/json`, and every new field is
`omitempty`, so a 1.3 peer receiving 1.4 traffic sees only keys it already
understands.

---

## License

This project is licensed under the [GNU Lesser General Public License v3.0 (LGPL-3.0)](LICENSE).
