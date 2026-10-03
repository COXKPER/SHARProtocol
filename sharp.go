package twoblade

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	ProtocolVersion = "SHARP/1.3"
	DefaultSharpPort = 5000
	DefaultHTTPPort  = 5001
	MaxUsernameLen   = 20
	MaxMessageSize   = 1024 * 1024       // 1MB
	MaxBufferSize    = 10 * 1024 * 1024  // 10MB
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

// Command represents messages exchanged over TCP
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
}

// Email represents email payload
type Email struct {
	From        string   `json:"from"`
	To          string   `json:"to"`
	Subject     string   `json:"subject"`
	Body        string   `json:"body"`
	ContentType string   `json:"content_type"`
	HTMLBody    *string  `json:"html_body,omitempty"`
	Attachments []string `json:"attachments,omitempty"`
	Hashcash    string   `json:"hashcash,omitempty"`
}

// Hashcash verification and generation
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

func HasLeadingZeroBits(sum [20]byte, bits int) bool {
	if bits <= 0 {
		return true
	}
	if bits > 160 {
		return false
	}
	bi := new(big.Int).SetBytes(sum[:])
	shift := uint(160 - bits)
	return bi.Rsh(bi, shift).Sign() == 0
}

func GenerateHashcash(resource string, bits int) (string, error) {
	date := FormatHashcashDate(time.Now().UTC())
	randBytes := make([]byte, 12)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}
	randStr := hex.EncodeToString(randBytes)

	var counter uint32
	buf := make([]byte, 4)
	for {
		binary.BigEndian.PutUint32(buf, counter)
		counterB64 := base64.RawStdEncoding.EncodeToString(buf)
		header := fmt.Sprintf("1:%d:%s:%s::%s:%s", bits, date, resource, randStr, counterB64)
		h := sha1.Sum([]byte(header))
		if HasLeadingZeroBits(h, bits) {
			return header, nil
		}
		counter++
	}
}

func VerifyHashcash(token, resource string, minBits int) error {
	parts := strings.Split(token, ":")
	if len(parts) < 7 || parts[0] != "1" {
		return fmt.Errorf("malformed hashcash token: len=%d token=%q", len(parts), token)
	}
	bits, err := strconv.Atoi(parts[1])
	if err != nil || bits < minBits {
		return fmt.Errorf("insufficient bits: got %d, want >= %d", bits, minBits)
	}
	// Resource is at parts[3]
	// Note: resource can contain colon if port is included, so parts after 3 could be shifted if split by colon!
	// Format is: 1:bits:date:resource:ext:rand:counter
	// But if resource is alice#example.com:1234, strings.Split(token, ":") will split on the port colon too!
	expectedPrefix := fmt.Sprintf("1:%s:%s:%s:", parts[1], parts[2], resource)
	if !strings.HasPrefix(token, expectedPrefix) {
		return fmt.Errorf("hashcash resource mismatch or format mismatch: prefix %q not in %q", expectedPrefix, token)
	}
	tokenTime, err := ParseHashcashDate(parts[2])
	if err != nil {
		return errors.New("invalid date in hashcash")
	}
	now := time.Now().UTC()
	if tokenTime.After(now.Add(2 * time.Minute)) {
		return errors.New("hashcash date in future")
	}
	if now.Sub(tokenTime) > 24*time.Hour {
		return errors.New("hashcash expired")
	}
	sum := sha1.Sum([]byte(token))
	if !HasLeadingZeroBits(sum, bits) {
		return errors.New("invalid hashcash proof of work")
	}
	return nil
}
