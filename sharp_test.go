package twoblade_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/COXKPER/SHARProtocol"
)

func TestSharpProtocolExchange(t *testing.T) {
	// Find free port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	domain := "example.com"
	received := make(chan twoblade.Email, 1)

	server := twoblade.NewServer(domain, port, func(username, d string) bool {
		return username == "alice" && d == domain
	}, func(email twoblade.Email) error {
		received <- email
		return nil
	})
	server.MinBits = 5 // Fast proof-of-work for tests

	if err := server.Start(); err != nil {
		t.Fatalf("server.Start() error: %v", err)
	}
	defer server.Close()

	time.Sleep(20 * time.Millisecond)

	toAddr := fmt.Sprintf("alice#%s:%d", domain, port)
	fromAddr := "bob#sender.com"

	// 1. Generate valid Hashcash
	token, err := twoblade.GenerateHashcash(toAddr, 5)
	if err != nil {
		t.Fatalf("GenerateHashcash error: %v", err)
	}

	client := twoblade.NewClient()
	email := twoblade.Email{
		From:        fromAddr,
		To:          toAddr,
		Subject:     "Hello from Go",
		Body:        "This is a SHARP email over Go TCP.",
		ContentType: "text/plain",
		Hashcash:    token,
	}

	// 2. Send email via client
	addrStr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := client.Send(addrStr, email); err != nil {
		t.Fatalf("client.Send() failed: %v", err)
	}

	select {
	case got := <-received:
		if got.Subject != email.Subject || got.Body != email.Body {
			t.Fatalf("received email mismatch: %+v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for email receipt")
	}

	// 3. Test replay attack / reused token rejection
	err = client.Send(addrStr, email)
	if err == nil {
		t.Fatal("expected failure on reused hashcash token, got success")
	}

	// 4. Test non-existent recipient rejection
	nonExistentEmail := email
	nonExistentEmail.To = fmt.Sprintf("charlie#%s:%d", domain, port)
	tok2, _ := twoblade.GenerateHashcash(nonExistentEmail.To, 5)
	nonExistentEmail.Hashcash = tok2
	err = client.Send(addrStr, nonExistentEmail)
	if err == nil {
		t.Fatal("expected 550 recipient not found error, got success")
	}
}

func TestAddressParsing(t *testing.T) {
	addr, err := twoblade.ParseAddress("user#domain.com:5000")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if addr.Username != "user" || addr.Domain != "domain.com" || addr.Port != 5000 {
		t.Fatalf("unexpected addr: %+v", addr)
	}

	_, err = twoblade.ParseAddress("bad-address")
	if err == nil {
		t.Fatal("expected error for address missing #")
	}
}
