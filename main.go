package main

import (
	"net"
	"os"
	"os/signal"
	"scanner/internal/clamav"
	"scanner/internal/config"
	"scanner/internal/logger"
	"scanner/internal/server"
	"syscall"

	pb "scanner/proto"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// TODO: gzip and hex deobfuscation
func main() {
	l := logger.Init()
	defer l.Sync()

	config.Cfg.Init("config.toml")
	clamav.Clam.Init()
	defer clamav.Clam.Free()

	// lis, err := net.Listen("unix", "/tmp/scanner.sock")
	lis, err := net.Listen("tcp", ":40400")
	if err != nil {
		l.Fatal("Could not create TCP listener", zap.Error(err))
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

	l.Info("gRPC server available at localhost:40400")
	s.Serve(lis)
}
