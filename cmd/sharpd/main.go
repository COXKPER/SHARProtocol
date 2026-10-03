package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/COXKPER/SHARProtocol"
)

func main() {
	domain := flag.String("domain", "localhost", "SHARP domain name")
	port := flag.Int("port", twoblade.DefaultSharpPort, "TCP port to listen on")
	flag.Parse()

	server := twoblade.NewServer(*domain, *port, func(username, d string) bool {
		// ponytail: static user check; connect to database in production
		return true
	}, func(email twoblade.Email) error {
		log.Printf("Received email: from=%s to=%s subject=%q bytes=%d",
			email.From, email.To, email.Subject, len(email.Body))
		return nil
	})

	if err := server.Start(); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
	fmt.Printf("SHARP/1.3 TCP server listening on :%d for domain %s\n", *port, *domain)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	fmt.Println("\nShutting down server...")
	_ = server.Close()
}
