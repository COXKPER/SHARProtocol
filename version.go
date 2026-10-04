package twoblade

import "strings"

// Protocol versions. ProtocolVersion is what this build prefers; 1.3 stays
// fully supported so peers that never upgrade keep working untouched.
const (
	ProtocolVersion       = "SHARP/1.4"
	LegacyProtocolVersion = "SHARP/1.3"
)

// SupportedVersions lists every version this build speaks, newest first.
// A Server accepts any of them; a Client offers them in order and falls back
// when a peer rejects the newest.
var SupportedVersions = []string{ProtocolVersion, LegacyProtocolVersion}

// Capability names exchanged in the HELLO handshake. Capabilities are how 1.4
// stays non-breaking: a peer that does not advertise one simply does not get
// the extension, and nothing about the base exchange changes.
const (
	// CapSignatures enables detached Ed25519 signatures over the message.
	CapSignatures = "signatures"
	// CapHashcashSHA256 enables version 2 hashcash tokens (SHA-256 digests).
	CapHashcashSHA256 = "hashcash-sha256"
	// CapMessageID enables a sender-assigned message id, so a receiver can
	// recognise a retried delivery instead of filing it twice.
	CapMessageID = "message-id"
)

// AllCapabilities is everything this build can offer.
var AllCapabilities = []string{CapSignatures, CapHashcashSHA256, CapMessageID}

// SupportsVersion reports whether v is a version this build can speak.
func SupportsVersion(v string) bool {
	for _, s := range SupportedVersions {
		if strings.EqualFold(strings.TrimSpace(v), s) {
			return true
		}
	}
	return false
}

// SupportsCapability reports whether want appears in an advertised list.
func SupportsCapability(advertised []string, want string) bool {
	for _, c := range advertised {
		if strings.EqualFold(strings.TrimSpace(c), want) {
			return true
		}
	}
	return false
}

// negotiateVersion picks the newest version both sides can speak.
//
// A peer states its preferred version in Protocol and may also list everything
// it understands in Supported. A 1.3 peer sends no Supported list at all, so we
// fall back to reading its single preferred version, which is exactly what a
// 1.4 server needs in order to keep talking to it.
//
// Returns the agreed version and whether one exists.
func negotiateVersion(peerProtocol string, peerSupported, ours []string) (string, bool) {
	peerSupported = append([]string{}, peerSupported...)
	if len(peerSupported) == 0 && strings.TrimSpace(peerProtocol) != "" {
		peerSupported = append(peerSupported, peerProtocol)
	}
	for _, mine := range ours {
		for _, theirs := range peerSupported {
			if strings.EqualFold(strings.TrimSpace(theirs), mine) {
				return mine, true
			}
		}
	}
	return "", false
}

// commonCapabilities returns the advertised capabilities we also understand.
func commonCapabilities(advertised, ours []string) []string {
	var out []string
	for _, mine := range ours {
		if SupportsCapability(advertised, mine) {
			out = append(out, mine)
		}
	}
	return out
}
