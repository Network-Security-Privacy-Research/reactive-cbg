package main

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "  ", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return "  " + string(b)
}
