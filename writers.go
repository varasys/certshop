package main

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
)

type pkiWriter interface {
	writeData(data *[]byte, path string, perms os.FileMode, overwrite bool)
	close()
}

type tgzWriter struct {
	gzWriter  *gzip.Writer
	tarWriter *tar.Writer
}

type fileWriter struct {
}

func (writer *tgzWriter) close() {
	if err := writer.tarWriter.Close(); err != nil {
		errorLog.Fatalf("Failed to close tar writer: %s", err)
	}
	if err := writer.gzWriter.Close(); err != nil {
		errorLog.Fatalf("Failed to close gzip writer: %s", err)
	}
}

func (writer *fileWriter) close() {
	// needed to satisfy pkiWriter interface, but not used since files are closed as soon as data is written
}

func newTgzWriter(dest io.Writer) *tgzWriter {
	gzWriter := gzip.NewWriter(dest)
	return &tgzWriter{gzWriter, tar.NewWriter(gzWriter)}
}

func newFileWriter() *fileWriter {
	return &fileWriter{}
}

func (writer *tgzWriter) writeData(data *[]byte, path string, perms os.FileMode, overwrite bool) {
	if err := writer.tarWriter.WriteHeader(&tar.Header{
		Name:    path,
		Mode:    int64(perms),
		Size:    int64(len(*data)),
		ModTime: runTime,
	}); err != nil {
		errorLog.Fatalf("Failed to write tar header %s: %s", path, err)
	}
	if _, err := writer.tarWriter.Write(*data); err != nil {
		errorLog.Fatalf("Failed to write tar data %s: %s", path, err)
	}
}

func (writer *fileWriter) writeData(data *[]byte, path string, perms os.FileMode, overwrite bool) {
	flags := os.O_WRONLY | os.O_CREATE
	if !overwrite {
		flags = flags | os.O_EXCL
		if _, err := os.Stat(path); err == nil {
			errorLog.Fatalf("File %s alread exists (use -overwrite to overwrite)", path)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), os.FileMode(0755)); err != nil {
		errorLog.Fatalf("Failed to create directory %s: %s", filepath.Dir(path), err)
	}
	if file, err := os.OpenFile(path, flags, perms); err != nil {
		errorLog.Fatalf("Failed to open file %s for writing: %s", path, err)
	} else {
		defer func() {
			if err = file.Close(); err != nil {
				errorLog.Fatalf("Failed to close file %s: %s", path, err)
			}
		}()
		if _, err = file.Write(*data); err != nil {
			errorLog.Fatalf("Failed to write data to file %s: %s", path, err)
		}
	}
}
