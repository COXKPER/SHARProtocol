package twoblade_test

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/COXKPER/SHARProtocol"
)

func testEmail() twoblade.Email {
	html := "<b>hi</b>"
	return twoblade.Email{
		From:        "bob#sender.com",
		To:          "alice#example.com",
		Subject:     "signature test",
		Body:        "body text",
		ContentType: "text/plain",
		HTMLBody:    &html,
		Attachments: []string{"a.txt"},
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	key, err := twoblade.GenerateSigningKey("bob#sender.com")
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	mail := testEmail()
	const id = "msg-1"

	sig, err := key.Sign(mail, id)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := twoblade.VerifySignature(key.PublicKey, mail, id, sig); err != nil {
		t.Fatalf("VerifySignature on untouched mail: %v", err)
	}
}

// TestSignatureCoversEveryField is the tamper test. Each mutation must break
// the signature, or the signature is decoration rather than a guarantee.
func TestSignatureCoversEveryField(t *testing.T) {
	key, err := twoblade.GenerateSigningKey("bob#sender.com")
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	base := testEmail()
	const id = "msg-1"

	sig, err := key.Sign(base, id)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	other := "<i>changed</i>"
	mutations := []struct {
		name string
		edit func(*twoblade.Email)
	}{
		{"subject", func(e *twoblade.Email) { e.Subject = "changed" }},
		{"body", func(e *twoblade.Email) { e.Body = "changed" }},
		{"from", func(e *twoblade.Email) { e.From = "eve#sender.com" }},
		{"to", func(e *twoblade.Email) { e.To = "carol#example.com" }},
		{"content type", func(e *twoblade.Email) { e.ContentType = "text/html" }},
		{"html body", func(e *twoblade.Email) { e.HTMLBody = &other }},
		{"attachments", func(e *twoblade.Email) { e.Attachments = []string{"a.txt", "b.txt"} }},
	}
	for _, m := range mutations {
		edited := base
		m.edit(&edited)
		if err := twoblade.VerifySignature(key.PublicKey, edited, id, sig); err == nil {
			t.Fatalf("signature still valid after changing %s; that field is not covered", m.name)
		}
	}

	// A different message id must also invalidate it.
	if err := twoblade.VerifySignature(key.PublicKey, base, "msg-2", sig); err == nil {
		t.Fatal("signature is not bound to the message id")
	}
}

// TestBodySubjectSwapIsDetected guards the length-prefix decision: without it,
// moving text between fields would leave the signature valid.
func TestBodySubjectSwapIsDetected(t *testing.T) {
	key, _ := twoblade.GenerateSigningKey("bob#sender.com")
	a := twoblade.Email{From: "bob#x.com", To: "alice#y.com", Subject: "ab", Body: "cd", ContentType: "text/plain"}
	b := twoblade.Email{From: "bob#x.com", To: "alice#y.com", Subject: "abc", Body: "d", ContentType: "text/plain"}

	sig, err := key.Sign(a, "id")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := twoblade.VerifySignature(key.PublicKey, b, "id", sig); err == nil {
		t.Fatal("subject/body boundary is ambiguous: swapping a character kept the signature valid")
	}
}

func TestVerifyRejectsWrongKeyAndGarbage(t *testing.T) {
	key, _ := twoblade.GenerateSigningKey("bob#sender.com")
	other, _ := twoblade.GenerateSigningKey("eve#sender.com")
	mail := testEmail()

	sig, err := key.Sign(mail, "id")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := twoblade.VerifySignature(other.PublicKey, mail, "id", sig); err == nil {
		t.Fatal("signature verified under the wrong public key")
	}
	if err := twoblade.VerifySignature(key.PublicKey, mail, "id", "not-base64!!"); err == nil {
		t.Fatal("garbage signature accepted")
	}
	if _, err := twoblade.DecodePublicKey("short"); err == nil {
		t.Fatal("short public key accepted")
	}
}

func TestTrustStorePinsOnFirstUse(t *testing.T) {
	store, err := twoblade.NewTrustStore(filepath.Join(t.TempDir(), "trust.json"))
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}
	key, _ := twoblade.GenerateSigningKey("bob#sender.com")
	mail := testEmail()

	sig, _ := key.Sign(mail, "id")
	result, err := store.VerifyPinned(mail, "id", key.PublicKeyBase64(), sig)
	if err != nil {
		t.Fatalf("first sighting should pin and verify: %v", err)
	}
	if result != twoblade.SignatureValid {
		t.Fatalf("result = %v, want valid", result)
	}
	if _, ok := store.Lookup("bob#sender.com"); !ok {
		t.Fatal("key was not pinned")
	}

	// A changed key must be reported, not accepted.
	eve, _ := twoblade.GenerateSigningKey("bob#sender.com")
	eveSig, _ := eve.Sign(mail, "id")
	result, err = store.VerifyPinned(mail, "id", eve.PublicKeyBase64(), eveSig)
	if err == nil {
		t.Fatal("key rotation was silently accepted")
	}
	if result != twoblade.SignatureUntrustedKey {
		t.Fatalf("result = %v, want untrusted-key", result)
	}

	// Forgetting the pin is the deliberate recovery path.
	if err := store.Forget("bob#sender.com"); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	result, err = store.VerifyPinned(mail, "id", eve.PublicKeyBase64(), eveSig)
	if err != nil || result != twoblade.SignatureValid {
		t.Fatalf("after Forget, want valid/nil, got %v/%v", result, err)
	}
}

func TestTrustStorePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "trust.json")
	store, err := twoblade.NewTrustStore(path)
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}
	mail := testEmail()
	key, _ := twoblade.GenerateSigningKey("bob#sender.com")
	sig, _ := key.Sign(mail, "id")
	if _, err := store.VerifyPinned(mail, "id", key.PublicKeyBase64(), sig); err != nil {
		t.Fatalf("VerifyPinned: %v", err)
	}

	reloaded, err := twoblade.NewTrustStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	pinned, ok := reloaded.Lookup("bob#sender.com")
	if !ok {
		t.Fatal("pin did not survive reload")
	}
	if pinned.PublicKey != key.PublicKeyBase64() {
		t.Fatal("reloaded pin has a different key")
	}
	if pinned.Fingerprint == "" {
		t.Fatal("fingerprint not recorded")
	}

	// Reloading must still catch a rotation.
	eve, _ := twoblade.GenerateSigningKey("bob#sender.com")
	eveSig, _ := eve.Sign(mail, "id")
	if result, err := reloaded.VerifyPinned(mail, "id", eve.PublicKeyBase64(), eveSig); err == nil || result != twoblade.SignatureUntrustedKey {
		t.Fatalf("reloaded store accepted a rotated key: %v/%v", result, err)
	}
}

func TestTrustStoreMissingFileIsEmpty(t *testing.T) {
	store, err := twoblade.NewTrustStore(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if len(store.List()) != 0 {
		t.Fatal("fresh store should be empty")
	}
	if _, err := twoblade.NewTrustStore(""); err != nil {
		t.Fatalf("empty path should be a memory-only store: %v", err)
	}
}

func TestFingerprintIsStableAndDistinct(t *testing.T) {
	a, _ := twoblade.GenerateSigningKey("a#x.com")
	b, _ := twoblade.GenerateSigningKey("b#x.com")
	if twoblade.Fingerprint(a.PublicKey) != twoblade.Fingerprint(a.PublicKey) {
		t.Fatal("fingerprint is not stable")
	}
	if twoblade.Fingerprint(a.PublicKey) == twoblade.Fingerprint(b.PublicKey) {
		t.Fatal("different keys produced the same fingerprint")
	}
}

// signedClientToServer wires a signing client to a verifying server and checks
// the handler receives a message the server vouched for.
func signedClientToServer(t *testing.T, configureServer func(*twoblade.Server), configureClient func(*twoblade.Client)) (twoblade.Email, []twoblade.SignatureResult) {
	t.Helper()
	var results []twoblade.SignatureResult
	serverResults := make(chan twoblade.SignatureResult, 4)

	port, received := startServer(t, func(s *twoblade.Server) {
		s.OnSignature = func(_ twoblade.Email, r twoblade.SignatureResult, _ error) {
			serverResults <- r
		}
		if configureServer != nil {
			configureServer(s)
		}
	})

	key, err := twoblade.GenerateSigningKey("bob#sender.com")
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	to := fmt.Sprintf("alice#example.com:%d", port)
	token, err := twoblade.GenerateHashcashV2(to, 5)
	if err != nil {
		t.Fatalf("hashcash: %v", err)
	}
	client := twoblade.NewClient()
	client.SigningKey = key
	client.Version = twoblade.ProtocolVersion
	if configureClient != nil {
		configureClient(client)
	}
	err = client.Send(fmt.Sprintf("127.0.0.1:%d", port), twoblade.Email{
		From: "bob#sender.com", To: to, Subject: "signed", Body: "b",
		ContentType: "text/plain", Hashcash: token,
	})
	if err != nil {
		t.Fatalf("signed send: %v", err)
	}

	var got twoblade.Email
	select {
	case got = <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("no signed mail delivered")
	}
	select {
	case r := <-serverResults:
		results = append(results, r)
	default:
	}
	return got, results
}

func TestSignedDeliveryEndToEnd(t *testing.T) {
	store, err := twoblade.NewTrustStore(filepath.Join(t.TempDir(), "trust.json"))
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}
	got, results := signedClientToServer(t, func(s *twoblade.Server) {
		s.TrustStore = store
	}, nil)

	if got.PublicKey == "" || got.Signature == "" {
		t.Fatal("signature did not survive the wire")
	}
	if got.ReceivedVersion != twoblade.ProtocolVersion {
		t.Fatalf("ReceivedVersion = %q, want 1.4", got.ReceivedVersion)
	}
	if len(results) != 1 || results[0] != twoblade.SignatureValid {
		t.Fatalf("OnSignature results = %v, want one valid", results)
	}
	if _, ok := store.Lookup("bob#sender.com"); !ok {
		t.Fatal("sender key was not pinned by the server")
	}
}

// TestUnsignedMailStillDeliversWithoutTrustStore is the non-exclusive check for
// signatures: a server that never opts in must behave exactly as before.
func TestUnsignedMailStillDeliversWithoutTrustStore(t *testing.T) {
	got, results := signedClientToServer(t, nil, func(c *twoblade.Client) {
		c.SigningKey = nil
	})
	if got.Subject != "signed" {
		t.Fatalf("unsigned mail did not deliver: %+v", got)
	}
	if len(results) != 1 || results[0] != twoblade.SignatureNone {
		t.Fatalf("results = %v, want one none", results)
	}
}

func TestRequireSignatureRejectsUnsigned(t *testing.T) {
	port, received := startServer(t, func(s *twoblade.Server) {
		s.RequireSignature = true
	})
	to := fmt.Sprintf("alice#example.com:%d", port)
	token, _ := twoblade.GenerateHashcash(to, 5)
	client := twoblade.NewClient()
	// Plain 1.3-shaped send with no signature.
	err := client.Send(fmt.Sprintf("127.0.0.1:%d", port), twoblade.Email{
		From: "bob#sender.com", To: to, Subject: "s", Body: "b",
		ContentType: "text/plain", Hashcash: token,
	})
	if err == nil {
		t.Fatal("unsigned mail accepted by a RequireSignature server")
	}
	if len(received) != 0 {
		t.Fatal("unsigned mail was delivered anyway")
	}
}

// TestTamperedSignatureRejectedEndToEnd sends a signature that is valid for a
// different message and confirms the server refuses to accept the mail.
func TestTamperedSignatureRejectedEndToEnd(t *testing.T) {
	store, _ := twoblade.NewTrustStore(filepath.Join(t.TempDir(), "trust.json"))
	port, received := startServer(t, func(s *twoblade.Server) {
		s.TrustStore = store
	})

	key, _ := twoblade.GenerateSigningKey("bob#sender.com")
	to := fmt.Sprintf("alice#example.com:%d", port)

	signed := twoblade.Email{From: "bob#sender.com", To: to, Subject: "real", Body: "body", ContentType: "text/plain"}
	sig, err := key.Sign(signed, "")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	token, _ := twoblade.GenerateHashcashV2(to, 5)
	forged := signed
	forged.Subject = "forged"
	forged.Hashcash = token
	forged.PublicKey = key.PublicKeyBase64()
	forged.Signature = sig

	// SigningKey is nil, so the client transmits the signature exactly as
	// given instead of re-signing over the forged content.
	client := twoblade.NewClient()
	client.Version = twoblade.ProtocolVersion
	err = client.Send(fmt.Sprintf("127.0.0.1:%d", port), forged)
	if err == nil {
		t.Fatal("server accepted a message whose signature covers different content")
	}
	if len(received) != 0 {
		t.Fatal("forged mail was delivered to the handler")
	}
}

func TestDedupeMessageIDSuppressesRetry(t *testing.T) {
	port, received := startServer(t, func(s *twoblade.Server) {
		s.DedupeMessageID = true
	})
	to := fmt.Sprintf("alice#example.com:%d", port)

	send := func(id string, bits int) error {
		token, err := twoblade.GenerateHashcashV2(to, bits)
		if err != nil {
			return err
		}
		client := twoblade.NewClient()
		client.Version = twoblade.ProtocolVersion
		return client.Send(fmt.Sprintf("127.0.0.1:%d", port), twoblade.Email{
			From: "bob#sender.com", To: to, Subject: "retry", Body: "b",
			ContentType: "text/plain", Hashcash: token, MessageID: id,
		})
	}

	// A real retry would mint fresh proof of work, because the server burns
	// each token once; the message id is what marks it as the same mail.
	if err := send("stable-id", 5); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if err := send("stable-id", 5); err == nil {
		t.Fatal("duplicate message id accepted")
	}

	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("first mail never arrived")
	}
	select {
	case <-received:
		t.Fatal("duplicate mail was filed twice")
	case <-time.After(150 * time.Millisecond):
	}
}
