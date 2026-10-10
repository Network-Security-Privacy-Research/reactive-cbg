package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Record is one line of the JSONL measurement log.
type Record struct {
	TS            time.Time `json:"ts"`
	NodeID        string    `json:"node_id"`
	SrcIP         string    `json:"src_ip"`
	SrcPort       uint16    `json:"src_port"`
	DstPort       uint16    `json:"dst_port"`
	Proto         string    `json:"proto"`
	RTTSamplesMS  []float64 `json:"rtt_samples_ms"`
	RTTMinMS      float64   `json:"rtt_min_ms"`
	CaptureMethod string    `json:"capture_method"`
	TTLObserved   uint8     `json:"ttl_observed,omitempty"`
	TCPOptsFP     string    `json:"tcp_opts_fp,omitempty"`
	IPID          uint16    `json:"ip_id,omitempty"`
	WindowSize    uint16    `json:"window_size,omitempty"`
	Flags         struct {
		ScanCandidate bool `json:"scan_candidate"`
		HandshakeDone bool `json:"handshake_done"`
		ResetByPeer   bool `json:"reset_by_peer"`
	} `json:"flags"`
}

// Writer is a size-rotating JSONL log writer, safe for concurrent use.
type Writer struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	keep     int
	f        *os.File
	n        int64
	enc      *json.Encoder

	compress    bool
	compressing sync.WaitGroup
}

func NewWriter(path string, maxMB, keep int, compress bool) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	w := &Writer{
		path:     path,
		maxBytes: int64(maxMB) * 1 << 20,
		keep:     keep,
		compress: compress,
	}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f, w.n, w.enc = f, st.Size(), json.NewEncoder(f)
	return nil
}

// rotate moves measurements.jsonl -> .1 -> .2 ... discarding beyond keep, and
// gzips the rotated files when compression is enabled.
//
// Rotated files are never appended to, so compressing them is free. It matters
// more than the disk saving suggests: the real risk is a scan burst filling the
// cap between central pulls, at which point rotation discards records silently.
// Roughly an order of magnitude more history fits before that happens.
//
// Compression runs in the background so a multi-second gzip on a 1 vCPU node
// does not stall the write path. The next rotation waits for it, which keeps
// the numbering from racing; rotations are minutes-to-days apart, so that wait
// is never contended in practice.
func (w *Writer) rotate() error {
	if err := w.f.Close(); err != nil {
		return err
	}

	// Any in-flight compression must finish before the slots are renumbered.
	w.compressing.Wait()

	if w.keep < 1 {
		// No history kept: truncate rather than renaming. Leaving the file in
		// place would make open() reopen it at full size and rotate forever.
		os.Remove(w.path)
		return w.open()
	}

	// Drop the oldest, in both possible forms.
	os.Remove(fmt.Sprintf("%s.%d.gz", w.path, w.keep))
	os.Remove(fmt.Sprintf("%s.%d", w.path, w.keep))

	// Shift the rest down. Both suffixes are handled so that toggling
	// log_compress on an existing node does not orphan its older files.
	for i := w.keep - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d.gz", w.path, i), fmt.Sprintf("%s.%d.gz", w.path, i+1))
		os.Rename(fmt.Sprintf("%s.%d", w.path, i), fmt.Sprintf("%s.%d", w.path, i+1))
	}

	if !w.compress {
		os.Rename(w.path, w.path+".1")
		return w.open()
	}

	// Stage under a name the shift loop ignores, then compress off the hot path.
	staged := w.path + ".rotating"
	if err := os.Rename(w.path, staged); err != nil {
		return err
	}
	w.compressing.Add(1)
	go func() {
		defer w.compressing.Done()
		if err := gzipFile(staged, w.path+".1.gz"); err != nil {
			// Keep the data uncompressed rather than losing it.
			log.Printf("compressing %s failed, keeping it raw: %v", staged, err)
			os.Rename(staged, w.path+".1")
			return
		}
		os.Remove(staged)
	}()
	return w.open()
}

// gzipFile compresses src to dst, writing via a temporary file so a crash
// mid-compression cannot leave a truncated .gz that looks complete.
func gzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	// Default level, chosen by measuring real measurement JSONL from node-1:
	// level 1 gives 9.3x, level 6 gives 11.4x for ~0.3s more per 49 MB, and
	// level 9 only reaches 11.8x for double the CPU of level 6. The extra 22%
	// is worth it on nodes with under 2 GB free, and the job is backgrounded
	// under Nice=10 with idle IO scheduling so it cannot disturb whatever else
	// the host is doing.
	zw, err := gzip.NewWriterLevel(out, gzip.DefaultCompression)
	if err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if _, err := io.Copy(zw, in); err != nil {
		zw.Close()
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := zw.Close(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// WriteRaw appends a pre-marshalled line, sharing the rotation and locking of
// the record path. The probe audit log is a different schema in a different
// file but wants identical size-capping behavior.
func (w *Writer) WriteRaw(b []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.n >= w.maxBytes {
		if err := w.rotate(); err != nil {
			return err
		}
	}
	n, err := w.f.Write(b)
	w.n += int64(n)
	return err
}

func (w *Writer) Write(r *Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.n >= w.maxBytes {
		if err := w.rotate(); err != nil {
			return err
		}
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	n, err := w.f.Write(b)
	w.n += int64(n)
	return err
}

// Close flushes and waits for any in-flight compression, so shutdown does not
// abandon a half-written .gz.
func (w *Writer) Close() error {
	w.mu.Lock()
	var err error
	if w.f != nil {
		err = w.f.Close()
		w.f = nil
	}
	w.mu.Unlock()
	w.compressing.Wait()
	return err
}
