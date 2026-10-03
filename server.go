package twoblade

import (
	"bufio"
	"encoding/json"
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

// Server implements SHARP TCP protocol
type Server struct {
	Domain       string
	Port         int
	MinBits      int
	UserExists   UserChecker
	OnEmail      EmailHandler
	listener     net.Listener
	mu           sync.Mutex
	usedTokens   map[string]time.Time
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
		quit:       make(chan struct{}),
	}
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
	step     string
	from     string
	to       string
	hashcash string
	email    Email
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
			if cmd.Protocol != ProtocolVersion {
				sendError(conn, fmt.Sprintf("Unsupported protocol version: %s", cmd.Protocol), 400)
				return
			}
			from, err := ParseAddress(cmd.ServerID)
			if err != nil {
				sendError(conn, "Invalid server_id format", 400)
				return
			}
			// ponytail: remote DNS SRV IP verification skipped; add when deploying federated internet nodes
			state.from = from.String()
			state.step = "MAIL_TO"
			_ = sendJSON(conn, Command{Type: "OK", Protocol: ProtocolVersion})

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
			if cmd.Hashcash == "" {
				sendError(conn, "Missing hashcash proof of work", 429)
				return
			}

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

			state.to = cmd.Address
			state.hashcash = cmd.Hashcash
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
					From:        state.from,
					To:          state.to,
					Subject:     cmd.Subject,
					Body:        cmd.Body,
					ContentType: ct,
					HTMLBody:    cmd.HTMLBody,
					Attachments: cmd.Attachments,
					Hashcash:    state.hashcash,
				}
				_ = sendJSON(conn, Command{Type: "OK", Message: "Email content received"})
			} else if cmd.Type == "END_DATA" {
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

// Client implements SHARP TCP sender
type Client struct {
	Timeout time.Duration
}

func NewClient() *Client {
	return &Client{Timeout: 10 * time.Second}
}

func (c *Client) Send(hostPort string, email Email) error {
	conn, err := net.DialTimeout("tcp", hostPort, c.Timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))

	reader := bufio.NewReader(conn)

	// Step 1: HELLO
	if err := sendJSON(conn, Command{Type: "HELLO", ServerID: email.From, Protocol: ProtocolVersion}); err != nil {
		return err
	}
	if err := expectOK(reader); err != nil {
		return fmt.Errorf("HELLO failed: %w", err)
	}

	// Step 2: MAIL_TO
	if err := sendJSON(conn, Command{Type: "MAIL_TO", Address: email.To, Hashcash: email.Hashcash}); err != nil {
		return err
	}
	if err := expectOK(reader); err != nil {
		return fmt.Errorf("MAIL_TO failed: %w", err)
	}

	// Step 3: DATA
	if err := sendJSON(conn, Command{Type: "DATA"}); err != nil {
		return err
	}
	if err := expectOK(reader); err != nil {
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
	if err := expectOK(reader); err != nil {
		return fmt.Errorf("EMAIL_CONTENT failed: %w", err)
	}

	// Step 5: END_DATA
	if err := sendJSON(conn, Command{Type: "END_DATA"}); err != nil {
		return err
	}
	if err := expectOK(reader); err != nil {
		return fmt.Errorf("END_DATA failed: %w", err)
	}

	return nil
}

func expectOK(r *bufio.Reader) error {
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	var resp Command
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		return err
	}
	if resp.Type != "OK" {
		return fmt.Errorf("[%d] %s", resp.Code, resp.Message)
	}
	return nil
}
