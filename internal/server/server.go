package server

import (
	"context"

	scannerv1 "github.com/ricehub-io/proto/gen/go/scanner/v1"
	"github.com/ricehub-io/scanner/internal/clamav"
	"github.com/ricehub-io/scanner/internal/staticanalysis"
	"github.com/ricehub-io/scanner/internal/zip"

	"go.uber.org/zap"
)

type ScannerServer struct {
	scannerv1.UnimplementedScannerServiceServer
}

func (s *ScannerServer) ScanFile(
	ctx context.Context,
	req *scannerv1.ScanRequest,
) (*scannerv1.ScanResponse, error) {
	l := zap.L()
	l.Info("Received request to scan file", zap.String("file_path", req.FilePath))

	files, err := zip.SafeUnzip(req.FilePath)
	if err != nil {
		return &scannerv1.ScanResponse{IsMalicious: true, Reason: []string{err.Error()}}, nil
	}

	if virusName, ret := clamav.Clam.Scan(req.FilePath); ret != nil {
		return &scannerv1.ScanResponse{
			IsMalicious: true,
			Reason:      []string{"anti-virus", virusName},
		}, nil
	}

	if detected := staticanalysis.StaticAnalysis(files); detected {
		return &scannerv1.ScanResponse{
			IsMalicious: true,
			Reason:      []string{"static analysis"},
		}, nil
	}

	return &scannerv1.ScanResponse{IsMalicious: false, Reason: []string{}}, nil
}
