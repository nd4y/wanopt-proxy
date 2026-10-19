package compress

import (
	"bytes"
	"io"
	"math/rand"
	"testing"
)

func TestAdaptiveSkipsIncompressibleAndResumes(t *testing.T) {
	random := make([]byte, 2<<20)
	rand.New(rand.NewSource(7)).Read(random)
	text := bytes.Repeat([]byte("compressible-data "), 1<<16)
	input := append(random, text...)
	var wire, decoded bytes.Buffer
	var sum Stats
	n, err := CopyObserved(&wire, bytes.NewReader(input), nil, func(s Stats) {
		sum.InputBytes += s.InputBytes
		sum.OutputBytes += s.OutputBytes
		sum.Attempted += s.Attempted
		sum.Skipped += s.Skipped
		sum.Compressed += s.Compressed
	})
	if err != nil || n != int64(len(input)) {
		t.Fatal(n, err)
	}
	if _, err := Decopy(&decoded, &wire); err != nil || !bytes.Equal(decoded.Bytes(), input) {
		t.Fatal("adaptive wire corrupted", err)
	}
	if sum.Skipped < 30 || sum.Compressed == 0 || sum.Attempted >= int64(len(input)/blockSize) {
		t.Fatalf("missing skip/resume: %+v", sum)
	}
	if sum.InputBytes != int64(len(input)) || sum.OutputBytes <= 0 {
		t.Fatal("accounting", sum)
	}
}

type byteReader struct{ remaining int }

func (r *byteReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	p[0] = 'x'
	r.remaining--
	return 1, nil
}
func TestTinyReadsNeverWaitForBlockOrAllocateEncoder(t *testing.T) {
	var wire, decoded bytes.Buffer
	var sum Stats
	_, err := CopyObserved(&wire, &byteReader{10}, nil, func(s Stats) { sum = s })
	if err != nil || sum.Attempted != 0 || sum.Skipped != 10 || wire.Len() != 60 {
		t.Fatal(err, sum, wire.Len())
	}
	if _, err := Decopy(&decoded, &wire); err != nil || decoded.String() != "xxxxxxxxxx" {
		t.Fatal(err)
	}
}
