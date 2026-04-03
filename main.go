package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"scanner/internal/config"
	"scanner/internal/scan"
	"scanner/internal/server"
	"syscall"

	pb "scanner/proto"

	"google.golang.org/grpc"
)

// TODO: score system to reduce false-positives
// TODO: gzip and hex deobfuscation
// TODO: add zap logger
func main() {
	config.Cfg.Init("config.toml")
	scan.Clam.Init()
	defer scan.Clam.Free()

	// lis, err := net.Listen("unix", "/tmp/scanner.sock")
	lis, err := net.Listen("tcp", ":40400")
	if err != nil {
		log.Fatalf("Failed to listen on unix socket: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterScannerServer(s, &server.Server{})

	// graceful shutdown
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		s.GracefulStop()
	}()

	log.Println("gRPC server available at :40400")
	s.Serve(lis)
}
