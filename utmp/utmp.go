//go:build linux

package utmp

import (
	"fmt"
	"log/slog"
	"os"
)

type FileReader struct {
	path   string
	logger *slog.Logger
}

func NewFileReader(path string, logger *slog.Logger) *FileReader {
	return &FileReader{path: path, logger: logger}
}

func (r *FileReader) ReadSessions() ([]Session, error) {
	data, err := os.ReadFile(r.path)
	if err != nil {
		return nil, fmt.Errorf("read utmp file %s: %w", r.path, err)
	}
	return parseRecords(data)
}
