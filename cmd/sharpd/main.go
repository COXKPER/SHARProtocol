package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/COXKPER/SHARProtocol"
)

func main() {
	domain := flag.String("domain", "localhost", "SHARP domain name")
	port := flag.Int("port", twoblade.DefaultSharpPort, "TCP port to listen on")
	// All three flags below are optional. Without them the daemon speaks
	// SHARP/1.4 but applies no 1.4 policy, so it still serves 1.3 peers.
	trustPath := flag.String("trust-store", "", "file to pin sender keys (enables signature verification)")
	requireSig := flag.Bool("require-signature", false, "reject unsigned mail (stops all 1.3 senders)")
	dedupe := flag.Bool("dedupe", true, "discard a retry that reuses a message id")
	flag.Parse()

	server := twoblade.NewServer(*domain, *port, func(username, d string) bool {
		// ponytail: static user check; connect to database in production
		return true
	}, func(email twoblade.Email) error {
		log.Printf("Received email: from=%s to=%s subject=%q bytes=%d version=%s signature=%s",
			email.From, email.To, email.Subject, len(email.Body), email.Version(), email.SignatureStatus())
		return nil
	})
	server.DedupeMessageID = *dedupe
	server.RequireSignature = *requireSig

	if *trustPath != "" {
		store, err := twoblade.NewTrustStore(filepath.Clean(*trustPath))
		if err != nil {
			log.Fatalf("trust store: %v", err)
		}
		server.TrustStore = store
	}

	if err := server.Start(); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
	fmt.Printf("%s TCP server listening on :%d for domain %s\n", twoblade.ProtocolVersion, *port, *domain)
	fmt.Printf("Supported versions: %v; capabilities: %v\n", twoblade.SupportedVersions, twoblade.AllCapabilities)
	if *requireSig {
		fmt.Println("Requiring signatures: mail without a valid signature will be refused.")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	fmt.Println("\nShutting down server...")
	_ = server.Close()
}
