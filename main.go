package main

import (
	"fmt"
	"log"
	"net"

	scannerv1 "github.com/ricehub-io/proto/gen/go/scanner/v1"
	"github.com/ricehub-io/scanner/internal/clamav"
	"github.com/ricehub-io/scanner/internal/config"
	"github.com/ricehub-io/scanner/internal/logger"
	"github.com/ricehub-io/scanner/internal/server"

	"google.golang.org/grpc"
)

const port = ":40400"

// TODO: gzip and hex deobfuscation
func main() {
	if err := run(); err != nil {
		log.Fatalln(err)
	}
}

func run() error {
	l := logger.Init()
	defer func() { _ = l.Sync() }()

	config.Cfg.Init("config.toml")
	if err := clamav.Clam.Init(); err != nil {
		return fmt.Errorf("clamav: %w", err)
	}
	defer clamav.Clam.Free()

	lis, err := net.Listen("tcp", port)
	if err != nil {
		return fmt.Errorf("net listen: %w", err)
	}

	grpcServer := grpc.NewServer()
	scannerv1.RegisterScannerServiceServer(grpcServer, &server.ScannerServer{})

	l.Sugar().Infof("gRPC server available at %s", port)
	if err := grpcServer.Serve(lis); err != nil {
		return fmt.Errorf("grpc serve: %w", err)
	}

	return nil
}
