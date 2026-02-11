package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestWriteCLIErrorJSON(t *testing.T) {
	var out bytes.Buffer
	writeCLIError(errors.New("boom"), true, &out)

	line := strings.TrimSpace(out.String())
	if line == "" {
		t.Fatal("expected JSON output, got empty string")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		t.Fatalf("expected valid JSON output, got %q: %v", line, err)
	}
	if got, _ := payload["message"].(string); got != "boom" {
		t.Fatalf("message = %q, want boom", got)
	}
	if got, _ := payload["level"].(string); got != "error" {
		t.Fatalf("level = %q, want error", got)
	}
	if _, ok := payload["timestamp"].(string); !ok {
		t.Fatalf("timestamp missing or not string: %#v", payload["timestamp"])
	}
}

func TestWriteCLIErrorText(t *testing.T) {
	var out bytes.Buffer
	writeCLIError(errors.New("boom"), false, &out)

	if got := out.String(); got != "boom\n" {
		t.Fatalf("text output = %q, want %q", got, "boom\n")
	}
}
