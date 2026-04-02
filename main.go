package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"scanner/internal/config"
	"scanner/internal/scan"
	"scanner/internal/zip"
	"syscall"

	pb "scanner/proto"

	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedScannerServer
}

func (s *server) ScanFile(ctx context.Context, req *pb.ScanRequest) (*pb.ScanResult, error) {
	files, err := zip.SafeUnzip(req.FilePath)
	if err != nil {
		return &pb.ScanResult{IsMalicious: true, Reason: []string{err.Error()}}, nil
	}

	if virusName, ret := scan.Clam.Scan(req.FilePath); ret != nil {
		return &pb.ScanResult{
			IsMalicious: true,
			Reason:      []string{"anti-virus", virusName},
		}, nil
	}

	if matched := scan.StaticAnalysis(files); len(matched) > 0 {
		return &pb.ScanResult{IsMalicious: true, Reason: matched}, nil
	}

	return &pb.ScanResult{IsMalicious: false, Reason: []string{}}, nil
}

// TODO: score system to reduce false-positives
// TODO: gzip and hex deobfuscation
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
	pb.RegisterScannerServer(s, &server{})

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
