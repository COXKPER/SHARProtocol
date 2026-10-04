package twoblade

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultSharpPort = 5000
	DefaultHTTPPort  = 5001
	MaxUsernameLen   = 20
	MaxMessageSize   = 1024 * 1024      // 1MB
	MaxBufferSize    = 10 * 1024 * 1024 // 10MB
)

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-!$%&'*/?=^@.]+$`)

// Address represents user#domain:port
type Address struct {
	Username string
	Domain   string
	Port     int
}

func (a Address) String() string {
	if a.Port > 0 {
		return fmt.Sprintf("%s#%s:%d", a.Username, a.Domain, a.Port)
	}
	return fmt.Sprintf("%s#%s", a.Username, a.Domain)
}

// ParseAddress parses address in the form user#domain[:port]
func ParseAddress(raw string) (Address, error) {
	parts := strings.SplitN(raw, "#", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Address{}, errors.New("invalid SHARP address format")
	}

	username := strings.ToLower(parts[0])
	if len(username) > MaxUsernameLen || !usernameRegex.MatchString(username) {
		return Address{}, errors.New("invalid username format")
	}

	domainPart := strings.ToLower(parts[1])
	port := 0
	if colonIdx := strings.LastIndex(domainPart, ":"); colonIdx != -1 {
		p, err := strconv.Atoi(domainPart[colonIdx+1:])
		if err != nil {
			return Address{}, errors.New("invalid port in address")
		}
		port = p
		domainPart = domainPart[:colonIdx]
	}

	if domainPart == "" {
		return Address{}, errors.New("invalid domain in address")
	}

	return Address{Username: username, Domain: domainPart, Port: port}, nil
}

// Command represents messages exchanged over TCP.
//
// The fields below Hashcash are all 1.4 additions and all omitempty. A 1.4
// sender therefore emits byte-identical JSON to a 1.3 sender when it has
// nothing new to say, and a 1.3 receiver simply ignores the extra keys it does
// not know (encoding/json drops unknown fields). That is what keeps 1.4 from
// being a breaking change.
type Command struct {
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

	// Supported lists every protocol version the peer can speak, newest first.
	// A 1.4 peer sends it; a 1.3 peer sends nothing and is understood anyway.
	Supported []string `json:"supported,omitempty"`
	// Capabilities lists the optional extensions the peer understands.
	Capabilities []string `json:"capabilities,omitempty"`
	// MessageID is a sender-assigned id, so a retried delivery can be
	// recognised as the same mail rather than filed twice.
	MessageID string `json:"message_id,omitempty"`
	// PublicKey is the sender's base64 Ed25519 key, and Signature the detached
	// signature over the message content.
	PublicKey string `json:"public_key,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// Email represents email payload.
//
// MessageID, PublicKey, Signature and ReceivedVersion are 1.4 additions. On
// the wire they only appear when a sender actually sets them, so a plain 1.3
// message serialises exactly as it always did.
type Email struct {
	From        string   `json:"from"`
	To          string   `json:"to"`
	Subject     string   `json:"subject"`
	Body        string   `json:"body"`
	ContentType string   `json:"content_type"`
	HTMLBody    *string  `json:"html_body,omitempty"`
	Attachments []string `json:"attachments,omitempty"`
	Hashcash    string   `json:"hashcash,omitempty"`

	// MessageID is set by the sender; a receiver may use it to discard a
	// duplicate delivery caused by a retry.
	MessageID string `json:"message_id,omitempty"`
	// PublicKey and Signature carry the sender's detached signature.
	PublicKey string `json:"public_key,omitempty"`
	Signature string `json:"signature,omitempty"`
	// ReceivedVersion records the protocol version this message arrived under,
	// so a handler can tell a signed 1.4 peer from an unsigned 1.3 one.
	ReceivedVersion string `json:"received_version,omitempty"`
}

// Version reports the protocol version this message arrived under, or
// "unknown" for a message built locally rather than received over the wire.
func (e Email) Version() string {
	if e.ReceivedVersion == "" {
		return "unknown"
	}
	return e.ReceivedVersion
}

// Signed reports whether the message carries signature material. It says
// nothing about whether that signature was checked or found good; that verdict
// comes from the server's OnSignature callback or TrustStore.
func (e Email) Signed() bool {
	return e.PublicKey != "" && e.Signature != ""
}

// SignatureStatus is a short label for logs and user interfaces.
func (e Email) SignatureStatus() string {
	if e.Signed() {
		return "signed"
	}
	return "unsigned"
}

// Hashcash timestamp helpers. Token minting and verification live in
// hashcash.go; these two are shared by both token versions.
func FormatHashcashDate(t time.Time) string {
	t = t.UTC()
	return fmt.Sprintf("%02d%02d%02d%02d%02d%02d",
		t.Year()%100, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
}

func ParseHashcashDate(s string) (time.Time, error) {
	if len(s) != 12 {
		return time.Time{}, errors.New("invalid hashcash date length")
	}
	y, _ := strconv.Atoi(s[0:2])
	m, _ := strconv.Atoi(s[2:4])
	d, _ := strconv.Atoi(s[4:6])
	h, _ := strconv.Atoi(s[6:8])
	min, _ := strconv.Atoi(s[8:10])
	sec, _ := strconv.Atoi(s[10:12])
	return time.Date(2000+y, time.Month(m), d, h, min, sec, 0, time.UTC), nil
}
