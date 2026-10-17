// Package compress implements optional, bounded block compression for protocol v2.
// Every block chooses raw or DEFLATE independently. Compression is opt-in: even
// incompressible input costs CPU, and framing adds five bytes per block.
package compress

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"io"
)

const (
	blockSize        = 32 * 1024
	markerRaw   byte = 0
	markerFlate byte = 1
)

// Keep at most two idle encoders. Active encoders are bounded by stream limits.
var encoders = make(chan *flate.Writer, 2)

func encoder(dst io.Writer) *flate.Writer {
	select {
	case w := <-encoders:
		w.Reset(dst)
		return w
	default:
		w, _ := flate.NewWriter(dst, flate.BestSpeed)
		return w
	}
}
func release(w *flate.Writer) {
	w.Reset(io.Discard)
	select {
	case encoders <- w:
	default:
	}
}

// Copy writes frames [mode:1][raw length:2][encoded length:2][data]. A single
// Read supplies a block so interactive protocols never wait for a full buffer.
func Copy(dst io.Writer, src io.Reader) (int64, error) {
	return CopyCounted(dst, src, nil)
}

// CopyCounted reports uncompressed bytes after a complete block reaches dst.
func CopyCounted(dst io.Writer, src io.Reader, onPayload func(int)) (int64, error) {
	buf := make([]byte, blockSize)
	var compressed bytes.Buffer
	w := encoder(&compressed)
	defer release(w)
	var total int64
	emptyReads := 0
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			emptyReads = 0
			compressed.Reset()
			w.Reset(&compressed)
			if _, err := w.Write(buf[:n]); err != nil {
				return total, err
			}
			if err := w.Close(); err != nil {
				return total, err
			}
			mode, data := markerRaw, buf[:n]
			if compressed.Len()*100 < n*90 {
				mode, data = markerFlate, compressed.Bytes()
			}
			var header [5]byte
			header[0] = mode
			binary.BigEndian.PutUint16(header[1:3], uint16(n))
			binary.BigEndian.PutUint16(header[3:5], uint16(len(data)))
			if err := writeFull(dst, header[:]); err != nil {
				return total, err
			}
			if err := writeFull(dst, data); err != nil {
				return total, err
			}
			total += int64(n)
			if onPayload != nil {
				onPayload(n)
			}
		} else if readErr == nil {
			emptyReads++
			if emptyReads >= 100 {
				return total, io.ErrNoProgress
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				readErr = nil
			}
			return total, readErr
		}
	}
}

// Decopy validates both frame sizes and decompressed length before forwarding a
// block. A truncated compressed stream is an error, never a successful EOF.
func Decopy(dst io.Writer, src io.Reader) (int64, error) {
	encoded := make([]byte, blockSize)
	decoded := make([]byte, blockSize+1)
	var total int64
	var header [5]byte
	for {
		n, err := io.ReadFull(src, header[:])
		if err == io.EOF && n == 0 {
			return total, nil
		}
		if err != nil {
			return total, err
		}
		rawLen, encLen := int(binary.BigEndian.Uint16(header[1:3])), int(binary.BigEndian.Uint16(header[3:5]))
		if rawLen == 0 || rawLen > blockSize || encLen == 0 || encLen > blockSize {
			return total, errors.New("compress: invalid block length")
		}
		if _, err := io.ReadFull(src, encoded[:encLen]); err != nil {
			return total, err
		}
		data := encoded[:encLen]
		switch header[0] {
		case markerRaw:
			if rawLen != encLen {
				return total, errors.New("compress: raw length mismatch")
			}
		case markerFlate:
			input := bytes.NewReader(data)
			reader := flate.NewReader(input)
			count, readErr := io.ReadFull(reader, decoded[:rawLen])
			extra, endErr := reader.Read(decoded[rawLen : rawLen+1])
			reader.Close()
			if count != rawLen || (readErr != nil || extra != 0 || endErr != io.EOF) || input.Len() != 0 {
				return total, errors.New("compress: invalid compressed block")
			}
			data = decoded[:rawLen]
		default:
			return total, errors.New("compress: unknown block mode")
		}
		if err := writeFull(dst, data); err != nil {
			return total, err
		}
		total += int64(len(data))
	}
}
func writeFull(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}
