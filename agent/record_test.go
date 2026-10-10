package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sampleRecord(i int) *Record {
	r := &Record{
		TS:            time.Date(2026, 8, 7, 14, 0, 0, i, time.UTC),
		NodeID:        "node-1",
		SrcIP:         fmt.Sprintf("203.0.113.%d", i%256),
		SrcPort:       uint16(30000 + i%20000),
		DstPort:       443,
		Proto:         "tcp",
		RTTSamplesMS:  []float64{38.07},
		RTTMinMS:      38.07,
		CaptureMethod: "pcap_synack_rst",
		TTLObserved:   49,
		TCPOptsFP:     "mss1460,sack,ts,nop,wscale7",
		IPID:          uint16(i),
		WindowSize:    64240,
	}
	r.Flags.ScanCandidate = true
	return r
}

func fileCount(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func TestRotationCompressesAndStaysReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "measurements.jsonl")
	// Tiny cap so rotation happens quickly.
	w, err := NewWriter(path, 1, 2, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12000; i++ {
		if err := w.Write(sampleRecord(i)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil { // waits for in-flight compression
		t.Fatalf("close: %v", err)
	}

	gz := path + ".1.gz"
	st, err := os.Stat(gz)
	if err != nil {
		t.Fatalf("expected %s: %v", gz, err)
	}
	if st.Size() == 0 {
		t.Fatal("compressed log is empty")
	}

	// The rotated file must still parse as JSONL after decompression -- a log we
	// cannot read back is worse than one that is merely large.
	f, err := os.Open(gz)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer zr.Close()

	n, raw := 0, int64(0)
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		raw += int64(len(line)) + 1
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("record %d does not parse: %v", n, err)
		}
		if r.NodeID != "node-1" || r.RTTMinMS != 38.07 {
			t.Fatalf("record %d corrupted: %+v", n, r)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if n == 0 {
		t.Fatal("no records recovered from the compressed log")
	}
	t.Logf("recovered %d records: %d bytes raw -> %d gz (%.1fx)",
		n, raw, st.Size(), float64(raw)/float64(st.Size()))

	// The uncompressed intermediate must not be left behind.
	if fileCount(path + ".rotating") {
		t.Error("staging file .rotating was left on disk")
	}
	if fileCount(path + ".1") {
		t.Error("uncompressed .1 left alongside .1.gz")
	}
}

// TestRotationHonoursKeep: files beyond keep must be discarded, or a burst
// quietly fills the disk on nodes with under 2 GB free.
func TestRotationHonoursKeep(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "measurements.jsonl")
	w, err := NewWriter(path, 1, 2, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40000; i++ {
		if err := w.Write(sampleRecord(i)); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()

	if !fileCount(path+".1.gz") || !fileCount(path+".2.gz") {
		t.Error("expected .1.gz and .2.gz to exist")
	}
	if fileCount(path + ".3.gz") {
		t.Error(".3.gz exists but keep=2")
	}
}

// TestKeepZeroDoesNotLoopForever: with keep=0 the active file was previously
// left in place, so open() reopened it at full size and every write rotated
// again. Guards against that regression.
func TestKeepZeroDoesNotLoopForever(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "measurements.jsonl")
	w, err := NewWriter(path, 1, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 20000; i++ {
			if err := w.Write(sampleRecord(i)); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("writes did not complete: rotation is looping")
	}
	w.Close()
	if fileCount(path + ".1") {
		t.Error("keep=0 should retain no rotated files")
	}
}

func TestUncompressedRotationStillWorks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "measurements.jsonl")
	w, err := NewWriter(path, 1, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12000; i++ {
		if err := w.Write(sampleRecord(i)); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	if !fileCount(path + ".1") {
		t.Error("expected uncompressed .1")
	}
	if fileCount(path + ".1.gz") {
		t.Error("compression disabled but .1.gz was produced")
	}
}
