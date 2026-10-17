package compress

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"testing"
)

type chunks struct {
	r    io.Reader
	size int
}

func (c chunks) Read(p []byte) (int, error) {
	if len(p) > c.size {
		p = p[:c.size]
	}
	return c.r.Read(p)
}
func randomData(n int) []byte {
	b := make([]byte, n)
	r := rand.New(rand.NewPCG(1, 2))
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}
func TestRoundTrip(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte("abcdef"), 20000), randomData(100000)} {
		for _, size := range []int{1, 512, 32768} {
			var wire, out bytes.Buffer
			n, err := Copy(&wire, chunks{bytes.NewReader(data), size})
			if err != nil || n != int64(len(data)) {
				t.Fatalf("copy n=%d err=%v", n, err)
			}
			n, err = Decopy(&out, &wire)
			if err != nil || n != int64(len(data)) || !bytes.Equal(out.Bytes(), data) {
				t.Fatalf("roundtrip n=%d err=%v", n, err)
			}
		}
	}
}
func TestMixedBlocksDoNotLockCompressionMode(t *testing.T) {
	data := append(bytes.Repeat([]byte("a"), 32768), randomData(32768)...)
	var wire bytes.Buffer
	if _, err := Copy(&wire, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	b := wire.Bytes()
	if b[0] != markerFlate {
		t.Fatal("compressible block not compressed")
	}
	next := 5 + int(binary.BigEndian.Uint16(b[3:5]))
	if b[next] != markerRaw {
		t.Fatal("incompressible block should be raw")
	}
	if len(b) > len(data)+10 {
		t.Fatal("expansion exceeds framing")
	}
}
func TestMalformedAndTruncatedFrames(t *testing.T) {
	cases := [][]byte{{1}, {2, 0, 1, 0, 1, 0}, {0, 0, 0, 0, 0}, {0, 0, 2, 0, 1, 1}, {0, 0, 2, 0, 2, 1}, {1, 0, 1, 0, 1, 0}}
	for _, b := range cases {
		if _, err := Decopy(io.Discard, bytes.NewReader(b)); err == nil {
			t.Fatalf("accepted malformed %x", b)
		}
	}
	var b bytes.Buffer
	Copy(&b, bytes.NewReader(bytes.Repeat([]byte("x"), 5000)))
	raw := b.Bytes()
	for cut := 1; cut < len(raw); cut++ {
		if _, err := Decopy(io.Discard, bytes.NewReader(raw[:cut])); err == nil {
			t.Fatalf("accepted truncated at %d", cut)
		}
	}
}
func FuzzDecopy(f *testing.F) {
	f.Add([]byte{0, 0, 1, 0, 1, 42})
	f.Add([]byte{1, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		Decopy(io.Discard, bytes.NewReader(b))
	})
}
func BenchmarkIncompressible(b *testing.B) {
	data := randomData(32768)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		Copy(io.Discard, bytes.NewReader(data))
	}
}
