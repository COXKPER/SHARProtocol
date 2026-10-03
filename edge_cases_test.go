package twoblade_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/COXKPER/SHARProtocol"
)

func startTestServer(t *testing.T, domain string) (*twoblade.Server, int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	srv := twoblade.NewServer(domain, port, func(user, d string) bool {
		return user == "alice" && d == domain
	}, func(email twoblade.Email) error {
		return nil
	})
	srv.MinBits = 5

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	return srv, port
}

func sendRawLine(t *testing.T, conn net.Conn, r *bufio.Reader, msg any) twoblade.Command {
	t.Helper()
	b, _ := json.Marshal(msg)
	_, err := conn.Write(append(b, '\n'))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	var resp twoblade.Command
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &resp); err != nil {
		t.Fatalf("json parse failed: %v (raw: %s)", err, line)
	}
	return resp
}

func TestProtocolFailureModes(t *testing.T) {
	srv, port := startTestServer(t, "example.com")
	defer srv.Close()

	addr := fmt.Sprintf("127.0.0.1:%d", port)

	t.Run("ProtocolVersionMismatch", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		r := bufio.NewReader(conn)

		resp := sendRawLine(t, conn, r, map[string]string{
			"type":      "HELLO",
			"server_id": "bob#sender.com",
			"protocol":  "SHARP/9.9",
		})
		if resp.Type != "ERROR" || resp.Code != 400 {
			t.Fatalf("expected 400 ERROR, got: %+v", resp)
		}
	})

	t.Run("UnexpectedSequenceOrder", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		r := bufio.NewReader(conn)

		resp := sendRawLine(t, conn, r, map[string]string{
			"type": "DATA",
		})
		if resp.Type != "ERROR" || resp.Code != 400 {
			t.Fatalf("expected 400 ERROR for out of order DATA, got: %+v", resp)
		}
	})

	t.Run("ForeignDomainRecipient", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		r := bufio.NewReader(conn)

		_ = sendRawLine(t, conn, r, map[string]string{
			"type":      "HELLO",
			"server_id": "bob#sender.com",
			"protocol":  twoblade.ProtocolVersion,
		})

		resp := sendRawLine(t, conn, r, map[string]string{
			"type":    "MAIL_TO",
			"address": "alice#otherdomain.com",
		})
		if resp.Type != "ERROR" || resp.Code != 451 {
			t.Fatalf("expected 451 foreign domain error, got: %+v", resp)
		}
	})

	t.Run("MissingHashcash", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		r := bufio.NewReader(conn)

		_ = sendRawLine(t, conn, r, map[string]string{
			"type":      "HELLO",
			"server_id": "bob#sender.com",
			"protocol":  twoblade.ProtocolVersion,
		})

		resp := sendRawLine(t, conn, r, map[string]string{
			"type":    "MAIL_TO",
			"address": fmt.Sprintf("alice#example.com:%d", port),
		})
		if resp.Type != "ERROR" || resp.Code != 429 {
			t.Fatalf("expected 429 for missing hashcash, got: %+v", resp)
		}
	})
}

func TestHashcashEdgeCases(t *testing.T) {
	resource := "alice#example.com"

	// 1. Valid token
	tok, err := twoblade.GenerateHashcash(resource, 6)
	if err != nil {
		t.Fatal(err)
	}
	if err := twoblade.VerifyHashcash(tok, resource, 6); err != nil {
		t.Fatalf("valid token failed: %v", err)
	}

	// 2. Resource mismatch
	if err := twoblade.VerifyHashcash(tok, "other#example.com", 6); err == nil {
		t.Fatal("expected error on resource mismatch")
	}

	// 3. Higher bit requirement than mined
	if err := twoblade.VerifyHashcash(tok, resource, 15); err == nil {
		t.Fatal("expected error on insufficient bit threshold")
	}

	// 4. Future timestamp (> 2 min)
	futureDate := twoblade.FormatHashcashDate(time.Now().Add(10 * time.Minute))
	futureTok := fmt.Sprintf("1:6:%s:%s::rand:count", futureDate, resource)
	if err := twoblade.VerifyHashcash(futureTok, resource, 6); err == nil {
		t.Fatal("expected error on future token date")
	}

	// 5. Expired timestamp (> 24 hours)
	pastDate := twoblade.FormatHashcashDate(time.Now().Add(-25 * time.Hour))
	pastTok := fmt.Sprintf("1:6:%s:%s::rand:count", pastDate, resource)
	if err := twoblade.VerifyHashcash(pastTok, resource, 6); err == nil {
		t.Fatal("expected error on expired token date")
	}
}

func TestAddressEdgeCases(t *testing.T) {
	invalidCases := []string{
		"",
		"no-hash",
		"#domain.com",
		"user#",
		"very_long_username_exceeding_twenty_chars#domain.com",
		"bad username with spaces#domain.com",
		"user#domain.com:notaport",
	}

	for _, tc := range invalidCases {
		if _, err := twoblade.ParseAddress(tc); err == nil {
			t.Fatalf("expected error parsing invalid address %q", tc)
		}
	}
}
