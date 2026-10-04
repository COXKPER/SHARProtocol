package twoblade

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// UserChecker verifies local user existence
type UserChecker func(username, domain string) bool

// EmailHandler processes incoming valid email
type EmailHandler func(email Email) error

// Server implements SHARP TCP protocol.
//
// Everything below OnEmail is optional 1.4 behaviour. Leaving all of it unset
// gives a server that behaves exactly like a 1.3 one while still accepting 1.4
// peers, which is the point: upgrading the library must not force a policy
// change on anyone.
type Server struct {
	Domain     string
	Port       int
	MinBits    int
	UserExists UserChecker
	OnEmail    EmailHandler

	// TrustStore verifies sender signatures and pins keys on first use. When
	// nil, signatures are still carried to OnEmail but not checked.
	TrustStore *TrustStore
	// RequireSignature rejects unsigned mail. Off by default, because turning
	// it on would drop every 1.3 peer's mail.
	RequireSignature bool
	// AcceptLegacyHashcash allows version 1 (SHA-1) tokens. Defaults to true
	// when unset via AllowHashcashV1 for clarity; a server that refuses them
	// would break every 1.3 sender, so the zero value must be permissive.
	RejectLegacyHashcash bool
	// Capabilities advertises optional extensions. Nil advertises
	// AllCapabilities, which describes what this build can actually do.
	Capabilities []string
	// OnSignature reports the verification outcome for each signed message.
	OnSignature func(email Email, result SignatureResult, detail error)
	// DedupeMessageID discards a repeat delivery carrying a MessageID already
	// seen from the same sender, so a sender's retry does not file twice.
	DedupeMessageID bool

	listener     net.Listener
	mu           sync.Mutex
	usedTokens   map[string]time.Time
	seenIDs      map[string]time.Time
	shutdownOnce sync.Once
	quit         chan struct{}
}

func NewServer(domain string, port int, userExists UserChecker, onEmail EmailHandler) *Server {
	if port <= 0 {
		port = DefaultSharpPort
	}
	return &Server{
		Domain:     strings.ToLower(domain),
		Port:       port,
		MinBits:    10, // ponytail: default 10 bits in dev/test; upgrade to 18 for production
		UserExists: userExists,
		OnEmail:    onEmail,
		usedTokens: make(map[string]time.Time),
		seenIDs:    make(map[string]time.Time),
		quit:       make(chan struct{}),
	}
}

// offeredCapabilities is what this server tells peers it understands.
func (s *Server) offeredCapabilities() []string {
	if s.Capabilities != nil {
		return s.Capabilities
	}
	return AllCapabilities
}

func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.Port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = l
	go s.cleanupLoop()
	go s.acceptLoop()
	return nil
}

func (s *Server) Close() error {
	s.shutdownOnce.Do(func() {
		close(s.quit)
		if s.listener != nil {
			s.listener.Close()
		}
	})
	return nil
}

func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.quit:
			return
		case now := <-ticker.C:
			s.mu.Lock()
			for token, exp := range s.usedTokens {
				if now.After(exp) {
					delete(s.usedTokens, token)
				}
			}
			// Message ids are remembered for the same window as hashcash
			// tokens: long enough to swallow a retry, short enough to forget.
			for id, exp := range s.seenIDs {
				if now.After(exp) {
					delete(s.seenIDs, id)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				continue
			}
		}
		go s.handleConnection(conn)
	}
}

type sessionState struct {
	step      string
	from      string
	to        string
	hashcash  string
	version   string
	peerCaps  []string
	messageID string
	publicKey string
	signature string
	email     Email
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	reader := bufio.NewReaderSize(conn, MaxBufferSize)
	state := &sessionState{step: "HELLO"}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) == 0 {
			continue
		}
		if len(line) > MaxMessageSize {
			sendError(conn, "Message too large", 413)
			return
		}

		var cmd Command
		if err := json.Unmarshal([]byte(line), &cmd); err != nil {
			sendError(conn, "Invalid JSON format", 400)
			return
		}

		switch state.step {
		case "HELLO":
			if cmd.Type != "HELLO" {
				sendError(conn, "Expected HELLO", 400)
				return
			}
			// Version negotiation, not a version gate. A 1.3 peer sends no
			// supported list, so negotiateVersion reads its single Protocol
			// value; a 1.4 peer may list several and we pick the newest we share.
			agreed, ok := negotiateVersion(cmd.Protocol, cmd.Supported, SupportedVersions)
			if !ok {
				sendError(conn, fmt.Sprintf("Unsupported protocol version: %s", cmd.Protocol), 400)
				return
			}
			state.version = agreed
			state.peerCaps = commonCapabilities(cmd.Capabilities, s.offeredCapabilities())
			from, err := ParseAddress(cmd.ServerID)
			if err != nil {
				sendError(conn, "Invalid server_id format", 400)
				return
			}
			// ponytail: remote DNS SRV IP verification skipped; add when deploying federated internet nodes
			state.from = from.String()
			state.step = "MAIL_TO"
			// Echo the agreed version and our capabilities so the sender knows
			// exactly which extensions it may use for this session.
			_ = sendJSON(conn, Command{
				Type:         "OK",
				Protocol:     agreed,
				Supported:    SupportedVersions,
				Capabilities: s.offeredCapabilities(),
			})

		case "MAIL_TO":
			if cmd.Type != "MAIL_TO" {
				sendError(conn, "Expected MAIL_TO", 400)
				return
			}
			to, err := ParseAddress(cmd.Address)
			if err != nil {
				sendError(conn, "Invalid recipient address format", 400)
				return
			}
			if to.Domain != s.Domain {
				sendError(conn, fmt.Sprintf("This server does not handle mail for %s", to.Domain), 451)
				return
			}
			if s.UserExists != nil && !s.UserExists(to.Username, to.Domain) {
				sendError(conn, "Recipient user not found", 550)
				return
			}
			if s.MinBits > 0 && cmd.Hashcash == "" {
				sendError(conn, "Missing hashcash proof of work", 429)
				return
			}

			if s.MinBits > 0 || cmd.Hashcash != "" {
				s.mu.Lock()
				if _, exists := s.usedTokens[cmd.Hashcash]; exists {
					s.mu.Unlock()
					sendError(conn, "Hashcash token already used", 429)
					return
				}
				if err := VerifyHashcash(cmd.Hashcash, cmd.Address, s.MinBits); err != nil {
					s.mu.Unlock()
					sendError(conn, fmt.Sprintf("Insufficient proof of work: %s", err), 429)
					return
				}
				s.usedTokens[cmd.Hashcash] = time.Now().Add(24 * time.Hour)
				s.mu.Unlock()
			}

			state.to = cmd.Address
			state.hashcash = cmd.Hashcash
			state.messageID = cmd.MessageID
			state.publicKey = cmd.PublicKey
			state.signature = cmd.Signature
			state.step = "DATA"
			_ = sendJSON(conn, Command{Type: "OK"})

		case "DATA":
			if cmd.Type != "DATA" {
				sendError(conn, "Expected DATA", 400)
				return
			}
			state.step = "RECEIVING_DATA"
			_ = sendJSON(conn, Command{Type: "OK"})

		case "RECEIVING_DATA":
			if cmd.Type == "EMAIL_CONTENT" {
				ct := cmd.ContentType
				if ct == "" {
					ct = "text/plain"
				}
				state.email = Email{
					From:            state.from,
					To:              state.to,
					Subject:         cmd.Subject,
					Body:            cmd.Body,
					ContentType:     ct,
					HTMLBody:        cmd.HTMLBody,
					Attachments:     cmd.Attachments,
					Hashcash:        state.hashcash,
					MessageID:       state.messageID,
					PublicKey:       state.publicKey,
					Signature:       state.signature,
					ReceivedVersion: state.version,
				}
				_ = sendJSON(conn, Command{Type: "OK", Message: "Email content received"})
			} else if cmd.Type == "END_DATA" {
				if err := s.verifyInbound(state); err != nil {
					sendError(conn, err.Error(), 550)
					return
				}
				if s.OnEmail != nil {
					if err := s.OnEmail(state.email); err != nil {
						sendError(conn, "Email processing failed", 500)
						return
					}
				}
				_ = sendJSON(conn, Command{Type: "OK", Message: "Email processed"})
				return
			} else {
				sendError(conn, "Expected EMAIL_CONTENT or END_DATA", 400)
				return
			}
		}
	}
}

// verifyInbound applies the optional 1.4 receiver policies to a session that has
// finished sending content: duplicate suppression, signature verification and,
// only if explicitly demanded, rejection of unsigned mail.
//
// Returning an error aborts the session with a permanent failure so the sender
// learns its mail was not accepted, rather than having it vanish.
func (s *Server) verifyInbound(state *sessionState) error {
	if s.DedupeMessageID && state.messageID != "" {
		key := strings.ToLower(state.from) + "\x00" + state.messageID
		s.mu.Lock()
		_, seen := s.seenIDs[key]
		if !seen {
			s.seenIDs[key] = time.Now().Add(24 * time.Hour)
		}
		s.mu.Unlock()
		if seen {
			return fmt.Errorf("duplicate message id %s from %s", state.messageID, state.from)
		}
	}

	signed := state.publicKey != "" && state.signature != ""
	if !signed {
		if s.RequireSignature {
			return errors.New("this server requires signed mail (SHARP/1.4 signature capability)")
		}
		if s.OnSignature != nil {
			s.OnSignature(state.email, SignatureNone, nil)
		}
		return nil
	}

	// A signed message is always checked, even when TrustStore is nil, because a
	// signature that does not cover the content is worse than no signature: it
	// looks like a guarantee and is not one.
	result := SignatureValid
	var detail error
	if s.TrustStore != nil {
		result, detail = s.TrustStore.VerifyPinned(state.email, state.messageID, state.publicKey, state.signature)
	} else if pub, err := DecodePublicKey(state.publicKey); err != nil {
		result, detail = SignatureInvalid, err
	} else if err := VerifySignature(pub, state.email, state.messageID, state.signature); err != nil {
		result, detail = SignatureInvalid, err
	}
	if s.OnSignature != nil {
		s.OnSignature(state.email, result, detail)
	}
	if result == SignatureInvalid {
		return fmt.Errorf("invalid signature: %v", detail)
	}
	if result == SignatureUntrustedKey {
		return fmt.Errorf("untrusted signing key: %v", detail)
	}
	return nil
}

func sendJSON(conn net.Conn, cmd Command) error {
	data, err := json.Marshal(cmd)
	if err != nil {
		return err
	}
	_, err = conn.Write(append(data, '\n'))
	return err
}

func sendError(conn net.Conn, msg string, code int) {
	_ = sendJSON(conn, Command{Type: "ERROR", Message: msg, Code: code})
}
