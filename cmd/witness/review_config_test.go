package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReviewConfigureRejectsAdapterThatFailsValidation(t *testing.T) {
	directory := t.TempDir()
	adapter := filepath.Join(directory, "adapter")
	if err := os.WriteFile(adapter, []byte("#!/bin/sh\nprintf 'adapter is unavailable\\n' >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "config", "config.json")
	err := route([]string{
		"review", "configure",
		"-out", configPath,
		"-adapter", "unusable",
		"-adapter-executable", adapter,
	})
	if err == nil || !strings.Contains(err.Error(), "adapter") {
		t.Fatalf("configure error = %v, want adapter validation error", err)
	}
	if _, statErr := os.Stat(configPath); !os.IsNotExist(statErr) {
		t.Fatalf("config stat = %v, want no config after failed adapter validation", statErr)
	}
}
