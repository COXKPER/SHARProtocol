package twoblade

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// Hashcash token versions.
//
// Version 1 is the original token, digested with SHA-1. Version 2 is the 1.4
// token, digested with SHA-256; it costs the sender the same work and is
// accepted by 1.4 peers, while 1.3 peers keep issuing and accepting version 1.
const (
	HashcashV1 = "1"
	HashcashV2 = "2"
)

// HashcashFieldCount is version, bits, date, resource, ext, rand, counter.
const HashcashFieldCount = 7

// HasLeadingZeroBits reports whether the digest begins with at least bits zero
// bits. The [20]byte signature is the historical SHA-1 shape; keep it for
// compatibility and use hasLeadingZeroBits internally for any digest length.
func HasLeadingZeroBits(sum [20]byte, bits int) bool {
	return hasLeadingZeroBits(sum[:], bits)
}

func hasLeadingZeroBits(sum []byte, bits int) bool {
	if bits <= 0 {
		return true
	}
	if bits > len(sum)*8 {
		return false
	}
	bi := new(big.Int).SetBytes(sum)
	bi.Rsh(bi, uint(len(sum)*8-bits))
	return bi.Sign() == 0
}

// Hashcash is a parsed proof-of-work token.
type Hashcash struct {
	Version  string
	Bits     int
	Date     time.Time
	Resource string
	Raw      string
}

// ParseHashcash splits a token into its fields.
//
// The resource may itself contain a colon (user#domain:port), so the middle
// fields are rejoined instead of trusting a naive split. This is stricter than
// the prefix comparison version 1 used, and accepts every token that produced
// a valid proof.
func ParseHashcash(token string) (Hashcash, error) {
	parts := strings.Split(token, ":")
	if len(parts) < HashcashFieldCount {
		return Hashcash{}, fmt.Errorf("malformed hashcash token: %d fields, want >= %d", len(parts), HashcashFieldCount)
	}
	if parts[0] != HashcashV1 && parts[0] != HashcashV2 {
		return Hashcash{}, fmt.Errorf("unsupported hashcash version %q", parts[0])
	}
	bits, err := strconv.Atoi(parts[1])
	if err != nil || bits < 0 {
		return Hashcash{}, fmt.Errorf("invalid hashcash bits %q", parts[1])
	}
	when, err := ParseHashcashDate(parts[2])
	if err != nil {
		return Hashcash{}, err
	}
	// parts[3 .. len-4] union into the resource; the trailing three are
	// ext, rand, counter.
	resource := strings.Join(parts[3:len(parts)-3], ":")
	if resource == "" {
		return Hashcash{}, errors.New("empty hashcash resource")
	}
	return Hashcash{Version: parts[0], Bits: bits, Date: when, Resource: resource, Raw: token}, nil
}

// HashcashBits returns the difficulty of a token, or 0 if it cannot be parsed.
func HashcashBits(token string) int {
	hc, err := ParseHashcash(token)
	if err != nil {
		return 0
	}
	return hc.Bits
}

// VerifyHashcash checks a token against the resource it should be bound to.
//
// Both token versions are accepted: verification follows the version the token
// declares, so a 1.3 peer's SHA-1 token still validates on a 1.4 server.
func VerifyHashcash(token, resource string, minBits int) error {
	hc, err := ParseHashcash(token)
	if err != nil {
		return err
	}
	if hc.Bits < minBits {
		return fmt.Errorf("insufficient bits: got %d, want >= %d", hc.Bits, minBits)
	}
	if !strings.EqualFold(hc.Resource, resource) {
		return fmt.Errorf("hashcash resource mismatch: token %q, expected %q", hc.Resource, resource)
	}
	now := time.Now().UTC()
	if hc.Date.After(now.Add(2 * time.Minute)) {
		return errors.New("hashcash date in future")
	}
	if now.Sub(hc.Date) > 24*time.Hour {
		return errors.New("hashcash expired")
	}

	var digest []byte
	switch hc.Version {
	case HashcashV2:
		sum := sha256.Sum256([]byte(token))
		digest = sum[:]
	default:
		sum := sha1.Sum([]byte(token))
		digest = sum[:]
	}
	if !hasLeadingZeroBits(digest, hc.Bits) {
		return errors.New("invalid hashcash proof of work")
	}
	return nil
}

// GenerateHashcash mints a version 1 (SHA-1) token. Retained so callers that
// must stay 1.3-compatible keep working.
func GenerateHashcash(resource string, bits int) (string, error) {
	return generateHashcash(HashcashV1, resource, bits)
}

// GenerateHashcashV2 mints a version 2 (SHA-256) token, the 1.4 default.
func GenerateHashcashV2(resource string, bits int) (string, error) {
	return generateHashcash(HashcashV2, resource, bits)
}

// BestHashcash mints the strongest token the peer will accept: version 2 when
// the peer advertised support, version 1 otherwise. This is what keeps the
// upgrade additive rather than breaking.
func BestHashcash(resource string, bits int, peerCapabilities []string) (string, error) {
	if SupportsCapability(peerCapabilities, CapHashcashSHA256) {
		return GenerateHashcashV2(resource, bits)
	}
	return GenerateHashcash(resource, bits)
}

func generateHashcash(version, resource string, bits int) (string, error) {
	if bits < 0 {
		return "", errors.New("hashcash bits must not be negative")
	}
	date := FormatHashcashDate(time.Now().UTC())
	randBytes := make([]byte, 12)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}
	randStr := hex.EncodeToString(randBytes)

	buf := make([]byte, 4)
	for counter := uint32(0); ; counter++ {
		binary.BigEndian.PutUint32(buf, counter)
		counterB64 := base64.RawStdEncoding.EncodeToString(buf)
		header := fmt.Sprintf("%s:%d:%s:%s::%s:%s", version, bits, date, resource, randStr, counterB64)
		var digest []byte
		if version == HashcashV2 {
			sum := sha256.Sum256([]byte(header))
			digest = sum[:]
		} else {
			sum := sha1.Sum([]byte(header))
			digest = sum[:]
		}
		if hasLeadingZeroBits(digest, bits) {
			return header, nil
		}
	}
}
