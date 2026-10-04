package twoblade_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/COXKPER/SHARProtocol"
)

// 1.3 wire structs, copied verbatim from the v1.0.1 source.
//
// The point of duplicating them here is that the interop tests must not use any
// 1.4 field. If a change ever makes a 1.4 peer depend on the new keys, one of
// these tests fails, because this struct cannot produce them.
type legacyCommand struct {
	Type        string   `json:"type"`
	ServerID    string   `json:"server_id,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	Address     string   `json:"address,omitempty"`
	Hashcash    string   `json:"hashcash,omitempty"`
	Subject     string   `json:"subject,omitempty"`
	Body        string   `json:"body,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
	HTMLBody    *string  `json:"html_body,omitempty"`
	Attachments []string `json:"attachments,omitempty"`
	Message     string   `json:"message,omitempty"`
	Code        int      `json:"code,omitempty"`
}

// legacySend talks to a server exactly as SHARP/1.3 did: HELLO with one
// protocol string, no supported list, no capabilities, SHA-1 hashcash.
func legacySend(t *testing.T, hostPort, from, to, subject, body string, bits int) error {
	t.Helper()
	conn, err := net.DialTimeout("tcp", hostPort, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)

	send := func(c legacyCommand) error {
		data, err := json.Marshal(c)
		if err != nil {
			return err
		}
		_, err = conn.Write(append(data, '\n'))
		return err
	}
	expectOK := func(step string) error {
		line, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("%s: %w", step, err)
		}
		var resp legacyCommand
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			return err
		}
		if resp.Type != "OK" {
			return fmt.Errorf("%s: [%d] %s", step, resp.Code, resp.Message)
		}
		return nil
	}

	// A 1.3 server emits the v1 SHA-1 token; a 1.3 client must too.
	token, err := twoblade.GenerateHashcash(to, bits)
	if err != nil {
		return err
	}

	if err := send(legacyCommand{Type: "HELLO", ServerID: from, Protocol: "SHARP/1.3"}); err != nil {
		return err
	}
	if err := expectOK("HELLO"); err != nil {
		return err
	}
	if err := send(legacyCommand{Type: "MAIL_TO", Address: to, Hashcash: token}); err != nil {
		return err
	}
	if err := expectOK("MAIL_TO"); err != nil {
		return err
	}
	if err := send(legacyCommand{Type: "DATA"}); err != nil {
		return err
	}
	if err := expectOK("DATA"); err != nil {
		return err
	}
	if err := send(legacyCommand{Type: "EMAIL_CONTENT", Subject: subject, Body: body, ContentType: "text/plain"}); err != nil {
		return err
	}
	if err := expectOK("EMAIL_CONTENT"); err != nil {
		return err
	}
	if err := send(legacyCommand{Type: "END_DATA"}); err != nil {
		return err
	}
	return expectOK("END_DATA")
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startServer runs a 1.4 server that accepts the single user alice.
func startServer(t *testing.T, configure func(*twoblade.Server)) (int, chan twoblade.Email) {
	t.Helper()
	port := freePort(t)
	domain := "example.com"
	received := make(chan twoblade.Email, 4)
	server := twoblade.NewServer(domain, port, func(username, d string) bool {
		return username == "alice" && d == domain
	}, func(email twoblade.Email) error {
		received <- email
		return nil
	})
	server.MinBits = 5
	if configure != nil {
		configure(server)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("server.Start(): %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	time.Sleep(20 * time.Millisecond)
	return port, received
}

// TestLegacy13ClientTo14Server is the central non-breaking guarantee: a peer
// that knows nothing about 1.4 is served exactly as before.
func TestLegacy13ClientTo14Server(t *testing.T) {
	port, received := startServer(t, nil)
	hostPort := fmt.Sprintf("127.0.0.1:%d", port)
	to := fmt.Sprintf("alice#example.com:%d", port)

	if err := legacySend(t, hostPort, "bob#sender.com", to, "hi from 1.3", "body", 5); err != nil {
		t.Fatalf("1.3 client rejected by 1.4 server: %v", err)
	}
	select {
	case got := <-received:
		if got.Subject != "hi from 1.3" {
			t.Fatalf("subject mismatch: %q", got.Subject)
		}
		// The server records the version it agreed on.
		if got.ReceivedVersion != twoblade.LegacyProtocolVersion {
			t.Fatalf("negotiated version = %q, want %q", got.ReceivedVersion, twoblade.LegacyProtocolVersion)
		}
		if got.Signature != "" || got.PublicKey != "" {
			t.Fatal("unsigned 1.3 message should arrive without signature fields")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for 1.3 mail")
	}
}

// Test14ServerAccepts13Hashcash pins that the SHA-1 token form still verifies
// on a 1.4 build, since every existing peer mints that form.
func Test14ServerAccepts13Hashcash(t *testing.T) {
	if err := twoblade.VerifyHashcash(mustToken(t, twoblade.GenerateHashcash), "alice#example.com", 5); err != nil {
		t.Fatalf("v1 hashcash no longer verifies: %v", err)
	}
	if err := twoblade.VerifyHashcash(mustToken(t, twoblade.GenerateHashcashV2), "alice#example.com", 5); err != nil {
		t.Fatalf("v2 hashcash does not verify: %v", err)
	}
}

func mustToken(t *testing.T, gen func(string, int) (string, error)) string {
	t.Helper()
	tok, err := gen("alice#example.com", 5)
	if err != nil {
		t.Fatalf("token generation: %v", err)
	}
	return tok
}

// Test14ClientToLegacy13Server proves the client degrades instead of failing.
// The listener speaks 1.3 only and rejects any other version string, which is
// exactly what a v1.0.1 server did.
func Test14ClientToLegacy13Server(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	got := make(chan legacyCommand, 16)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					var cmd legacyCommand
					if err := json.Unmarshal([]byte(line), &cmd); err != nil {
						return
					}
					got <- cmd
					// v1.0.1 behaviour: anything not exactly "SHARP/1.3" is refused.
					if cmd.Type == "HELLO" && cmd.Protocol != "SHARP/1.3" {
						resp, _ := json.Marshal(legacyCommand{
							Type: "ERROR", Message: "Unsupported protocol version: " + cmd.Protocol, Code: 400,
						})
						_, _ = conn.Write(append(resp, '\n'))
						return
					}
					resp, _ := json.Marshal(legacyCommand{Type: "OK"})
					_, _ = conn.Write(append(resp, '\n'))
					if cmd.Type == "END_DATA" {
						return
					}
				}
			}(conn)
		}
	}()

	to := "alice#example.com"
	token, err := twoblade.GenerateHashcash(to, 5)
	if err != nil {
		t.Fatalf("hashcash: %v", err)
	}
	client := twoblade.NewClient()
	err = client.Send(l.Addr().String(), twoblade.Email{
		From: "bob#sender.com", To: to, Subject: "s", Body: "b",
		ContentType: "text/plain", Hashcash: token,
	})
	if err != nil {
		t.Fatalf("client should have fallen back to 1.3, got: %v", err)
	}

	// The first HELLO must be the 1.4 offer, then the 1.3 retry.
	var first *legacyCommand
	select {
	case c := <-got:
		first = &c
	case <-time.After(2 * time.Second):
		t.Fatal("no HELLO received")
	}
	if first.Type != "HELLO" || first.Protocol != twoblade.ProtocolVersion {
		t.Fatalf("first HELLO = %+v, want protocol %s", first, twoblade.ProtocolVersion)
	}
}

// TestVersionNegotiation covers the negotiation edge case that matters most: a
// peer that sends only a preferred version and no supported list.
func TestVersionNegotiation(t *testing.T) {
	port, received := startServer(t, nil)
	hostPort := fmt.Sprintf("127.0.0.1:%d", port)
	to := fmt.Sprintf("alice#example.com:%d", port)
	if err := legacySend(t, hostPort, "bob#sender.com", to, "neg", "b", 5); err != nil {
		t.Fatalf("legacy send: %v", err)
	}
	select {
	case got := <-received:
		if got.ReceivedVersion != twoblade.LegacyProtocolVersion {
			t.Fatalf("got version %q, want 1.3", got.ReceivedVersion)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

// TestUnknownVersionRejected keeps the failure mode intact for a real stranger.
func TestUnknownVersionRejected(t *testing.T) {
	port, _ := startServer(t, nil)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	msg, _ := json.Marshal(legacyCommand{Type: "HELLO", ServerID: "bob#sender.com", Protocol: "SHARP/9.9"})
	if _, err := conn.Write(append(msg, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp legacyCommand
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Type != "ERROR" || resp.Code != 400 {
		t.Fatalf("expected 400 rejection, got %+v", resp)
	}
}
