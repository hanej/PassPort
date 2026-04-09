package logging

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewRotatableFile_WriteAndClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	rf, err := NewRotatableFile(path)
	if err != nil {
		t.Fatalf("NewRotatableFile: %v", err)
	}
	defer rf.Close()

	n, err := rf.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 bytes written, got %d", n)
	}

	// Verify file contents.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("expected 'hello', got %q", data)
	}
}

func TestRotatableFile_Reopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rotate.log")
	rf, err := NewRotatableFile(path)
	if err != nil {
		t.Fatalf("NewRotatableFile: %v", err)
	}
	defer rf.Close()

	if _, err := rf.Write([]byte("before")); err != nil {
		t.Fatalf("Write before reopen: %v", err)
	}

	if err := rf.Reopen(); err != nil {
		t.Fatalf("Reopen: %v", err)
	}

	if _, err := rf.Write([]byte("after")); err != nil {
		t.Fatalf("Write after reopen: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}
	if string(data) != "beforeafter" {
		t.Errorf("expected 'beforeafter', got %q", data)
	}
}

func TestNewRotatableFile_BadPath(t *testing.T) {
	_, err := NewRotatableFile("/nonexistent/directory/test.log")
	if err == nil {
		t.Fatal("expected error for bad path, got nil")
	}
}

func TestRotatableFile_Close(t *testing.T) {
	path := filepath.Join(t.TempDir(), "close.log")
	rf, err := NewRotatableFile(path)
	if err != nil {
		t.Fatalf("NewRotatableFile: %v", err)
	}
	if err := rf.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestRotatableFile_WriteConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.log")
	rf, err := NewRotatableFile(path)
	if err != nil {
		t.Fatalf("NewRotatableFile: %v", err)
	}
	defer rf.Close()

	// Concurrent writes should not race.
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			rf.Write([]byte("x")) //nolint:errcheck
			done <- struct{}{}
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestRotatableFile_Reopen_CloseError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reopen-close-err.log")
	rf, err := NewRotatableFile(path)
	if err != nil {
		t.Fatalf("NewRotatableFile: %v", err)
	}
	// Close the underlying file directly to make the next Close() call fail.
	rf.file.Close()

	// Reopen should return an error because the file is already closed.
	if err := rf.Reopen(); err == nil {
		t.Error("expected error when Reopen called with already-closed file")
	}
}

func TestRotatableFile_Reopen_OpenFileError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reopen-open-err.log")
	rf, err := NewRotatableFile(path)
	if err != nil {
		t.Fatalf("NewRotatableFile: %v", err)
	}
	defer rf.file.Close() // final cleanup if anything goes wrong

	// Remove the directory so that OpenFile fails after we close.
	if err := rf.file.Close(); err != nil {
		t.Fatalf("closing underlying file: %v", err)
	}
	// Replace the file with a closed one to make the first Close() in Reopen succeed.
	// Then remove the directory so that reopening fails.
	newF, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("opening devnull: %v", err)
	}
	rf.file = newF

	// Remove parent directory so OpenFile will fail.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("removing dir: %v", err)
	}

	if err := rf.Reopen(); err == nil {
		t.Error("expected error when Reopen called with invalid path")
	}
}
