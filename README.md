# SHARProtocol (Go Implementation)

[![Go Reference](https://pkg.go.dev/badge/github.com/COXKPER/SHARProtocol.svg)](https://pkg.go.dev/github.com/COXKPER/SHARProtocol)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)](LICENSE)

Go implementation of **SHARP** (**S**elf-**H**osted **A**ddress **R**outing **P**rotocol) - a decentralized email protocol and client specification from [twoblade](https://github.com/outpoot/twoblade) using the `#` symbol for addressing (e.g. `user#domain.com`).

---

## Protocol Overview (SHARP/1.3)

- **Addressing:** `user#domain.com` (optionally `user#domain.com:port`).
- **Transport:** Line-delimited JSON over TCP.
- **Default Ports:** 5000 (SHARP TCP protocol), 5001 (HTTP API).
- **Discovery:** DNS SRV record `_sharp._tcp.<domain>` falling back to `sharp.<domain>:5000`.
- **Anti-Spam:** Hashcash Proof-of-Work (SHA-1 prefix bits, e.g. 5 trivial, 10 weak, 18 recommended).

### Message Exchange Flow

```
Client                                  Server
  |                                       |
  | -------- HELLO (server_id) ---------> |
  | <------- OK (SHARP/1.3) ------------- |
  |                                       |
  | -------- MAIL_TO (+ Hashcash) ------> |
  | <------- OK ------------------------- |
  |                                       |
  | -------- DATA ----------------------> |
  | <------- OK ------------------------- |
  |                                       |
  | -------- EMAIL_CONTENT -------------> |
  | <------- OK (Received) -------------- |
  |                                       |
  | -------- END_DATA ------------------> |
  | <------- OK (Processed) ------------- |
```

---

## Installation

```bash
go get github.com/COXKPER/SHARProtocol@v1.0.0
```

---

## Quick Start

### 1. Running a SHARP Server

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
		fmt.Printf("Received email from %s: %s\n", email.From, email.Subject)
		return nil
	})

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

### 3. Running the Standalone Daemon

```bash
cd twoblade-go
go run ./cmd/sharpd -domain example.com -port 5000
```

---

## License

This project is licensed under the [GNU Lesser General Public License v3.0 (LGPL-3.0)](LICENSE).
