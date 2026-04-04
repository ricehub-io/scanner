package server

import (
	"context"
	"scanner/internal/clamav"
	"scanner/internal/staticanalysis"
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

	if virusName, ret := clamav.Clam.Scan(req.FilePath); ret != nil {
		return &pb.ScanResult{
			IsMalicious: true,
			Reason:      []string{"anti-virus", virusName},
		}, nil
	}

	if detected := staticanalysis.StaticAnalysis(files); detected {
		return &pb.ScanResult{
			IsMalicious: true,
			Reason:      []string{"static analysis"},
		}, nil
	}

	return &pb.ScanResult{IsMalicious: false, Reason: []string{}}, nil
}
