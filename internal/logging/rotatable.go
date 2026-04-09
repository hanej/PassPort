// Package logging provides a file writer that supports log rotation via SIGHUP.
package logging

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// RotatableFile is an io.Writer that can reopen its underlying file on demand.
// After the external log rotation tool renames the file, call Reopen() to start
// writing to a new file at the original path. This is typically triggered by SIGHUP.
type RotatableFile struct {
	mu   sync.Mutex
	path string
	file *os.File
}

// NewRotatableFile opens the file at path for append-only writing.
func NewRotatableFile(path string) (*RotatableFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening log file %s: %w", path, err)
	}
	return &RotatableFile{path: path, file: f}, nil
}

// Write implements io.Writer.
func (r *RotatableFile) Write(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.file.Write(p)
}

// Reopen closes the current file and opens a new one at the same path.
// This allows external tools (logrotate, newsyslog) to rotate the file.
func (r *RotatableFile) Reopen() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.file.Close(); err != nil {
		return fmt.Errorf("closing old log file: %w", err)
	}

	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("reopening log file %s: %w", r.path, err)
	}
	r.file = f
	return nil
}

// Close closes the underlying file.
func (r *RotatableFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.file.Close()
}

// Ensure RotatableFile implements io.WriteCloser.
var _ io.WriteCloser = (*RotatableFile)(nil)
