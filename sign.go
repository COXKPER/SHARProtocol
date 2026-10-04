package twoblade

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// What signing does and does not prove, because the difference matters:
//
// A signature proves the holder of a private key wrote the message, and that
// nothing between sender and receiver altered it. It does NOT prove the key
// belongs to the person named in From. Binding a key to a name is exactly what
// TOFU pinning (TrustStore) adds: the first key you see for an address is
// remembered, and any later change is reported loudly rather than accepted.
//
// There is no certificate authority here and no third party to trust.

// SignatureResult describes the outcome of verifying a signed message.
type SignatureResult int

const (
	// SignatureNone means the message carried no signature at all. Normal for
	// a 1.3 peer and not an error.
	SignatureNone SignatureResult = iota
	// SignatureValid means the signature matches and the key is pinned to the
	// sender, or was pinned on this first sighting.
	SignatureValid
	// SignatureUntrustedKey means the signature verifies, but the key differs
	// from the one previously pinned for this address. Treat as suspect.
	SignatureUntrustedKey
	// SignatureInvalid means the signature does not match the message.
	SignatureInvalid
)

func (r SignatureResult) String() string {
	switch r {
	case SignatureNone:
		return "none"
	case SignatureValid:
		return "valid"
	case SignatureUntrustedKey:
		return "untrusted-key"
	case SignatureInvalid:
		return "invalid"
	default:
		return "unknown"
	}
}

// SigningKey is an Ed25519 identity for one SHARP address.
type SigningKey struct {
	Address    string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	CreatedAt  time.Time
}

// GenerateSigningKey creates a fresh signing identity.
func GenerateSigningKey(address string) (*SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &SigningKey{
		Address:    strings.ToLower(strings.TrimSpace(address)),
		PrivateKey: priv,
		PublicKey:  pub,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// PublicKeyBase64 is the form exchanged on the wire and pinned in the store.
func (k *SigningKey) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(k.PublicKey)
}

// signableBytes is the canonical byte string a signature covers.
//
// Every field that a receiver would act on is included, in a fixed order, with
// a length prefix per field. Without the lengths, moving a character between
// Subject and Body would leave the concatenation unchanged and two different
// messages would share one signature.
func signableBytes(mail Email, messageID string) []byte {
	h := sha256.New()
	write := func(parts ...string) {
		for _, p := range parts {
			fmt.Fprintf(h, "%d:", len(p))
			h.Write([]byte(p))
		}
	}
	html := ""
	if mail.HTMLBody != nil {
		html = *mail.HTMLBody
	}
	write(
		ProtocolVersion,
		strings.ToLower(mail.From),
		strings.ToLower(mail.To),
		messageID,
		mail.Subject,
		mail.Body,
		mail.ContentType,
		html,
		strings.Join(mail.Attachments, "\n"),
	)
	return h.Sum(nil)
}

// Sign returns the base64 detached signature for a message.
func (k *SigningKey) Sign(mail Email, messageID string) (string, error) {
	if len(k.PrivateKey) != ed25519.PrivateKeySize {
		return "", errors.New("signing key is not initialised")
	}
	sig := ed25519.Sign(k.PrivateKey, signableBytes(mail, messageID))
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifySignature checks a detached signature against a public key.
func VerifySignature(pub ed25519.PublicKey, mail Email, messageID, signature string) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid public key length")
	}
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("signature is not valid base64: %w", err)
	}
	if !ed25519.Verify(pub, signableBytes(mail, messageID), raw) {
		return errors.New("signature does not match message")
	}
	return nil
}

// DecodePublicKey parses the base64 public key from the wire.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("public key is not valid base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// Fingerprint is a short, human-readable key identifier for logs and UIs.
// SHA-256 over the public key, first 8 bytes, grouped in fours.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	h := hex.EncodeToString(sum[:8])
	var b strings.Builder
	for i := 0; i < len(h); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(h[i : i+4])
	}
	return b.String()
}

// TrustStore remembers the public key first seen for each address (trust on
// first use) and persists it so the memory survives a restart.
//
// A pinned key is never silently replaced. A different key is reported as
// untrusted until an operator removes the pin, because an unnoticed key change
// is precisely the attack pinning exists to catch.
type TrustStore struct {
	mu     sync.Mutex
	path   string
	pinned map[string]PinnedKey
}

// PinnedKey is the record kept for one address.
type PinnedKey struct {
	Address     string    `json:"address"`
	PublicKey   string    `json:"public_key"`
	Fingerprint string    `json:"fingerprint"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// NewTrustStore loads the pins at path. A missing file is an empty store, not
// an error, so a first run needs no setup.
func NewTrustStore(path string) (*TrustStore, error) {
	ts := &TrustStore{path: path, pinned: map[string]PinnedKey{}}
	if path == "" {
		return ts, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ts, nil
	}
	if err != nil {
		return nil, err
	}
	var stored []PinnedKey
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("read trust store %s: %w", path, err)
	}
	for _, pk := range stored {
		ts.pinned[strings.ToLower(pk.Address)] = pk
	}
	return ts, nil
}

// Lookup returns the pinned key for an address, if any.
func (t *TrustStore) Lookup(address string) (PinnedKey, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	pk, ok := t.pinned[strings.ToLower(strings.TrimSpace(address))]
	return pk, ok
}

// Pin records a key for an address on first use.
func (t *TrustStore) Pin(address string, pub ed25519.PublicKey) (PinnedKey, error) {
	key := strings.ToLower(strings.TrimSpace(address))
	now := time.Now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	if existing, ok := t.pinned[key]; ok && existing.PublicKey != base64.StdEncoding.EncodeToString(pub) {
		return existing, fmt.Errorf("address %s is already pinned to fingerprint %s", key, existing.Fingerprint)
	}
	pk := PinnedKey{
		Address:     key,
		PublicKey:   base64.StdEncoding.EncodeToString(pub),
		Fingerprint: Fingerprint(pub),
		FirstSeen:   now,
		LastSeen:    now,
	}
	if existing, ok := t.pinned[key]; ok {
		pk.FirstSeen = existing.FirstSeen
	}
	t.pinned[key] = pk
	return pk, t.saveLocked()
}

// Forget removes a pin, which is the deliberate act an operator takes after
// confirming out of band that a correspondent really did rotate their key.
func (t *TrustStore) Forget(address string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.pinned, strings.ToLower(strings.TrimSpace(address)))
	return t.saveLocked()
}

// List returns every pin, sorted by address.
func (t *TrustStore) List() []PinnedKey {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.listLocked()
}

// listLocked builds the pin list. Callers must already hold t.mu; saveLocked
// needs it and must not re-enter List, which would deadlock.
func (t *TrustStore) listLocked() []PinnedKey {
	out := make([]PinnedKey, 0, len(t.pinned))
	for _, pk := range t.pinned {
		out = append(out, pk)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

func (t *TrustStore) saveLocked() error {
	if t.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(t.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(t.listLocked(), "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(t.path, data)
}

// VerifyPinned verifies a signed message against the trust store, pinning the
// key on first sighting and refusing to accept a changed key.
func (t *TrustStore) VerifyPinned(mail Email, messageID, publicKeyB64, signature string) (SignatureResult, error) {
	pub, err := DecodePublicKey(publicKeyB64)
	if err != nil {
		return SignatureInvalid, err
	}
	if err := VerifySignature(pub, mail, messageID, signature); err != nil {
		return SignatureInvalid, err
	}
	encoded := base64.StdEncoding.EncodeToString(pub)
	if existing, ok := t.Lookup(mail.From); ok {
		if existing.PublicKey != encoded {
			return SignatureUntrustedKey, fmt.Errorf(
				"signing key for %s changed: pinned %s, received %s",
				mail.From, existing.Fingerprint, Fingerprint(pub))
		}
		return SignatureValid, nil
	}
	if _, err := t.Pin(mail.From, pub); err != nil {
		return SignatureUntrustedKey, err
	}
	return SignatureValid, nil
}

// writeFileAtomic writes via a temporary file and rename so a crash mid-write
// cannot leave a truncated trust store behind.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".trust-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
