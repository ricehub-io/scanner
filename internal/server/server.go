package server

import (
	"context"
	"scanner/internal/scan"
	"scanner/internal/zip"
	pb "scanner/proto"
)

type Server struct {
	pb.UnimplementedScannerServer
}

func (s *Server) ScanFile(ctx context.Context, req *pb.ScanRequest) (*pb.ScanResult, error) {
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
