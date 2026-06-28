// Package compress provides adaptive, per-direction stream compression for the
// tunnel relay. Each direction is self-describing: the sender probes the first
// chunk of data, and only enables DEFLATE when that sample is actually
// compressible (so already-compressed payloads — TLS, video, archives — are
// passed through untouched and don't waste CPU). A one-byte marker tells the
// receiver which path was taken.
package compress

import (
	"compress/flate"
	"io"
)

const (
	markerRaw   byte = 0
	markerFlate byte = 1

	probeSize      = 32 * 1024 // bytes sampled to estimate compressibility
	compressIfPct  = 90        // use DEFLATE only if sample shrinks below this %
	flateLevel     = flate.DefaultCompression
)

// Copy streams src->dst, transparently compressing when the data looks
// compressible. It writes a leading marker byte describing the choice. Returns
// the number of *uncompressed* payload bytes copied.
func Copy(dst io.Writer, src io.Reader) (int64, error) {
	// Sample the first chunk with a single bounded read.
	sample := make([]byte, probeSize)
	n, rerr := io.ReadAtLeast(src, sample, 1)
	if n == 0 {
		// Nothing to send; still emit a raw marker so the reader stays in sync.
		_, werr := dst.Write([]byte{markerRaw})
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			return 0, werr
		}
		if werr != nil {
			return 0, werr
		}
		return 0, rerr
	}
	sample = sample[:n]

	if !compressible(sample) {
		if _, err := dst.Write([]byte{markerRaw}); err != nil {
			return 0, err
		}
		w, err := writeAll(dst, sample)
		if err != nil {
			return w, err
		}
		if rerr != nil {
			return w, ignoreEOF(rerr)
		}
		c, err := io.Copy(dst, src)
		return w + c, err
	}

	if _, err := dst.Write([]byte{markerFlate}); err != nil {
		return 0, err
	}
	fw, err := flate.NewWriter(dst, flateLevel)
	if err != nil {
		return 0, err
	}
	written, err := flushingCopy(fw, sample, src, rerr)
	cerr := fw.Close()
	if err != nil {
		return written, err
	}
	return written, cerr
}

// Decopy reverses Copy: it reads the marker and streams the (decompressed)
// payload to dst.
func Decopy(dst io.Writer, src io.Reader) (int64, error) {
	var marker [1]byte
	if _, err := io.ReadFull(src, marker[:]); err != nil {
		return 0, ignoreEOF(err)
	}
	switch marker[0] {
	case markerRaw:
		return io.Copy(dst, src)
	case markerFlate:
		fr := flate.NewReader(src)
		defer fr.Close()
		return io.Copy(dst, fr)
	default:
		return 0, io.ErrUnexpectedEOF
	}
}

// flushingCopy writes the already-read prefix then pumps src into fw, flushing
// after every read so interactive traffic is not stuck in the DEFLATE buffer.
func flushingCopy(fw *flate.Writer, prefix []byte, src io.Reader, prefixErr error) (int64, error) {
	var total int64
	if len(prefix) > 0 {
		if _, err := fw.Write(prefix); err != nil {
			return total, err
		}
		total += int64(len(prefix))
		if err := fw.Flush(); err != nil {
			return total, err
		}
	}
	if prefixErr != nil {
		return total, ignoreEOF(prefixErr)
	}
	buf := make([]byte, 64*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := fw.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
			if ferr := fw.Flush(); ferr != nil {
				return total, ferr
			}
		}
		if err != nil {
			return total, ignoreEOF(err)
		}
	}
}

// compressible reports whether a DEFLATE pass shrinks the sample enough to be
// worth it.
func compressible(sample []byte) bool {
	var counter countWriter
	fw, err := flate.NewWriter(&counter, flateLevel)
	if err != nil {
		return false
	}
	if _, err := fw.Write(sample); err != nil {
		return false
	}
	if err := fw.Close(); err != nil {
		return false
	}
	return int(counter)*100 < len(sample)*compressIfPct
}

type countWriter int

func (c *countWriter) Write(p []byte) (int, error) { *c += countWriter(len(p)); return len(p), nil }

func writeAll(dst io.Writer, b []byte) (int64, error) {
	n, err := dst.Write(b)
	return int64(n), err
}

func ignoreEOF(err error) error {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return nil
	}
	return err
}
