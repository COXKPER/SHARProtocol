package twoblade

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// Client implements the SHARP TCP sender.
//
// Every field added in 1.4 is optional. A zero Client sends a plain 1.3-shaped
// message: it offers 1.4 first, and if the peer only speaks 1.3 it quietly
// retries with 1.3 instead of failing.
type Client struct {
	Timeout time.Duration
	// SigningKey signs outgoing mail when set. Nil sends unsigned mail.
	SigningKey *SigningKey
	// Version overrides the preferred protocol version, for pinning a client
	// to 1.3 while diagnosing a peer.
	Version string
	// Capabilities overrides what this client claims to support. Nil claims
	// all capabilities the build actually implements.
	Capabilities []string
	// HashcashBits, when above zero, asks Client to mint the proof of work
	// itself rather than trusting email.Hashcash to be pre-filled.
	HashcashBits int
	// RequireSignatures makes Send fail rather than deliver unsigned mail to a
	// peer that cannot verify signatures. Off by default, so signing is
	// additive: a correspondent on 1.3 still receives the mail.
	RequireSignatures bool
	// OnDegrade reports each time a 1.4 feature is dropped for a peer that
	// cannot honour it. Worth logging, because an unsigned send should be a
	// visible fact and not a silent assumption.
	OnDegrade func(reason string)
}

func NewClient() *Client {
	return &Client{Timeout: 10 * time.Second}
}

// offeredVersions is the version list this client will advertise.
func (c *Client) offeredVersions() []string {
	if c.Version == "" {
		return SupportedVersions
	}
	return append([]string{c.Version}, SupportedVersions...)
}

func (c *Client) offeredCapabilities() []string {
	if c.Capabilities != nil {
		return c.Capabilities
	}
	return AllCapabilities
}

// NewMessageID returns a random id suitable for Email.MessageID. A sender that
// keeps the id stable across its own retries lets the receiver collapse the
// duplicates instead of filing the mail several times.
func NewMessageID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// A weaker id is still better than no id; the value only needs to be
		// unique enough to spot a retry within a day.
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// Send delivers one message. It tries the newest shared version first and
// falls back once when the peer rejects it, so one binary talks to 1.3 and 1.4
// servers without configuration.
func (c *Client) Send(hostPort string, email Email) error {
	versions := c.offeredVersions()
	var lastErr error
	for i, version := range versions {
		err := c.sendVersion(hostPort, email, version)
		if err == nil {
			return nil
		}
		lastErr = err
		// Only a version rejection is worth retrying lower; a bad address or a
		// failed proof of work will fail identically on the older version.
		if !isVersionRejection(err) || i == len(versions)-1 {
			return err
		}
	}
	return lastErr
}

func isVersionRejection(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unsupported protocol version") ||
		strings.Contains(msg, "protocol version") ||
		strings.Contains(msg, "version not supported")
}

// sendVersion performs one full session at a fixed protocol version.
func (c *Client) sendVersion(hostPort string, email Email, version string) error {
	conn, err := net.DialTimeout("tcp", hostPort, c.Timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	reader := bufio.NewReader(conn)

	// Step 1: HELLO. Supported and Capabilities tell a 1.4 peer what we can
	// do; a 1.3 peer ignores both keys.
	if err := sendJSON(conn, Command{
		Type:         "HELLO",
		ServerID:     email.From,
		Protocol:     version,
		Supported:    c.offeredVersions(),
		Capabilities: c.offeredCapabilities(),
	}); err != nil {
		return err
	}
	resp, err := expectOK(reader)
	if err != nil {
		return fmt.Errorf("HELLO failed: %w", err)
	}
	// Trust the server's advertised list over our own assumption: it may speak
	// a newer version than we asked for.
	peerCaps := resp.Capabilities

	// A message id must be assigned before signing, because the signature
	// covers it. Assign it once here so a retry reuses the same value.
	if email.MessageID == "" && SupportsCapability(peerCaps, CapMessageID) {
		email.MessageID = NewMessageID()
	}

	// Sign over exactly the fields that will be transmitted. Signing is done
	// before MAIL_TO because the signature travels with that command.
	if c.SigningKey != nil {
		if !SupportsCapability(peerCaps, CapSignatures) {
			if c.RequireSignatures {
				return fmt.Errorf("peer does not advertise %q and RequireSignatures is set", CapSignatures)
			}
			// Deliver anyway, unsigned, but say so. Dropping the signature
			// silently would leave the sender believing mail was signed.
			if c.OnDegrade != nil {
				c.OnDegrade(fmt.Sprintf("peer does not advertise %q; sending unsigned mail", CapSignatures))
			}
		} else {
			sig, err := c.SigningKey.Sign(email, email.MessageID)
			if err != nil {
				return err
			}
			email.Signature = sig
			email.PublicKey = c.SigningKey.PublicKeyBase64()
		}
	}

	// Step 2: MAIL_TO, carrying the proof of work and any 1.4 extras.
	token := email.Hashcash
	if token == "" && c.HashcashBits > 0 {
		token, err = BestHashcash(email.To, c.HashcashBits, peerCaps)
		if err != nil {
			return err
		}
		email.Hashcash = token
	}
	if err := sendJSON(conn, Command{
		Type:      "MAIL_TO",
		Address:   email.To,
		Hashcash:  token,
		MessageID: email.MessageID,
		PublicKey: email.PublicKey,
		Signature: email.Signature,
	}); err != nil {
		return err
	}
	if _, err := expectOK(reader); err != nil {
		return fmt.Errorf("MAIL_TO failed: %w", err)
	}

	// Step 3: DATA
	if err := sendJSON(conn, Command{Type: "DATA"}); err != nil {
		return err
	}
	if _, err := expectOK(reader); err != nil {
		return fmt.Errorf("DATA failed: %w", err)
	}

	// Step 4: EMAIL_CONTENT
	if err := sendJSON(conn, Command{
		Type:        "EMAIL_CONTENT",
		Subject:     email.Subject,
		Body:        email.Body,
		ContentType: email.ContentType,
		HTMLBody:    email.HTMLBody,
		Attachments: email.Attachments,
	}); err != nil {
		return err
	}
	if _, err := expectOK(reader); err != nil {
		return fmt.Errorf("EMAIL_CONTENT failed: %w", err)
	}

	// Step 5: END_DATA
	if err := sendJSON(conn, Command{Type: "END_DATA"}); err != nil {
		return err
	}
	if _, err := expectOK(reader); err != nil {
		return fmt.Errorf("END_DATA failed: %w", err)
	}

	return nil
}

func expectOK(r *bufio.Reader) (Command, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return Command{}, err
	}
	var resp Command
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		return Command{}, err
	}
	if resp.Type != "OK" {
		return resp, fmt.Errorf("[%d] %s", resp.Code, resp.Message)
	}
	return resp, nil
}
