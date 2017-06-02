package main

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
)

// PKIWriter is an interface for writing to either files or a .tgz archive
type PKIWriter interface {
	WriteData(data []byte, path string, perms os.FileMode)
	Close()
}

// TGZWriter is an interface for writing to .tgz archive
type TGZWriter struct {
	gzWriter  *gzip.Writer
	tarWriter *tar.Writer
}

// FileWriter is an interface for writing to files
type FileWriter struct {
}

// StdoutWriter is an interface for writing to stdout
type StdoutWriter struct {
}

// NewStdoutWriter creater and return a new StdoutWriter
func NewStdoutWriter() *StdoutWriter {
	return &StdoutWriter{}
}

// WriteData writes data to stdout
// the path and perms arguments are ignored
func (writer *StdoutWriter) WriteData(data []byte, path string, perms os.FileMode) {
	if _, err := os.Stdout.Write(data); err != nil {
		ErrorLog.Fatalf("Failed to write to stdout: %s", err)
	}
}

// Close flushes output to stdout
func (writer *StdoutWriter) Close() {
	os.Stdout.Sync()
}

// Close closes the writer
func (writer *TGZWriter) Close() {
	if err := writer.tarWriter.Close(); err != nil {
		ErrorLog.Fatalf("Failed to close tar writer: %s", err)
	}
	if err := writer.gzWriter.Close(); err != nil {
		ErrorLog.Fatalf("Failed to close gzip writer: %s", err)
	}
}

// Close closes the writer
func (writer *FileWriter) Close() {
	// needed to satisfy pkiWriter interface, but not used since files are closed as soon as data is written
}

// NewTgzWriter creates a new TGZWriter outputting to dest
func NewTgzWriter(dest io.Writer) *TGZWriter {
	gzWriter := gzip.NewWriter(dest)
	return &TGZWriter{gzWriter, tar.NewWriter(gzWriter)}
}

// NewFileWriter ceates a new FileWriter outputting to the local filesystem
func NewFileWriter() *FileWriter {
	return &FileWriter{}
}

// WriteData writes a header and data block in the .tgz archive
func (writer *TGZWriter) WriteData(data []byte, path string, perms os.FileMode) {
	if err := writer.tarWriter.WriteHeader(&tar.Header{
		Name:    path,
		Mode:    int64(perms),
		Size:    int64(len(data)),
		ModTime: RunTime,
	}); err != nil {
		ErrorLog.Fatalf("Failed to write tar header %s: %s", path, err)
	}
	if _, err := writer.tarWriter.Write(data); err != nil {
		ErrorLog.Fatalf("Failed to write tar data %s: %s", path, err)
	}
}

// WriteData writes data to the local filesystem
func (writer *FileWriter) WriteData(data []byte, path string, perms os.FileMode) {
	flags := os.O_WRONLY | os.O_CREATE
	if !Overwrite {
		flags = flags | os.O_EXCL
		if _, err := os.Stat(path); err == nil {
			ErrorLog.Fatalf("File %s alread exists (use -overwrite to overwrite)", path)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), os.FileMode(0755)); err != nil {
		ErrorLog.Fatalf("Failed to create directory %s: %s", filepath.Dir(path), err)
	}
	if file, err := os.OpenFile(path, flags, perms); err != nil {
		ErrorLog.Fatalf("Failed to open file %s for writing: %s", path, err)
	} else {
		defer func() {
			if err = file.Close(); err != nil {
				ErrorLog.Fatalf("Failed to close file %s: %s", path, err)
			}
		}()
		if _, err = file.Write(data); err != nil {
			ErrorLog.Fatalf("Failed to write data to file %s: %s", path, err)
		}
	}
}
