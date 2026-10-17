package protocol

import (
	"bytes"
	"net"
	"testing"
)

func TestAddressesRoundTrip(t *testing.T) {
	for _, s := range []string{"127.0.0.1:80", "[::1]:443", "example.com:53", "example.com.:53"} {
		a, err := ParseAddress(s)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ReadAddress(bytes.NewReader(a.Encode(nil)))
		if err != nil || a.String() != b.String() {
			t.Fatalf("%s: %v", s, err)
		}
	}
}
func TestInvalidAddresses(t *testing.T) {
	for _, s := range []string{":80", "bad host:80", "foo/bar:80", "-foo.example:80", "foo..bar:80", "host:65536"} {
		if _, err := ParseAddress(s); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
func TestDatagramBoundaries(t *testing.T) {
	a := Address{Atyp: AtypIPv4, IP: net.IPv4(127, 0, 0, 1), Port: 53}
	for _, size := range []int{0, MaxUDPPayload, MaxUDPPayload + 1} {
		b := EncodeDatagram(1, a, make([]byte, size))
		_, err := DecodeDatagram(b)
		if (err == nil) != (size <= MaxUDPPayload) {
			t.Fatalf("size=%d err=%v", size, err)
		}
	}
}
func TestProtocolVersionRejectsV1(t *testing.T) {
	if _, err := ReadStreamRequest(bytes.NewReader([]byte{1, 1, 0, 1, 127, 0, 0, 1, 0, 80})); err == nil {
		t.Fatal("accepted v1")
	}
}
func FuzzAddress(f *testing.F) {
	f.Add([]byte{1, 127, 0, 0, 1, 0, 80})
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := ReadAddress(bytes.NewReader(b))
		if err == nil {
			round, err := ReadAddress(bytes.NewReader(a.Encode(nil)))
			if err != nil || round.String() != a.String() {
				t.Fatal("roundtrip")
			}
		}
	})
}
func FuzzDatagram(f *testing.F) {
	f.Add([]byte{2, 1, 1, 127, 0, 0, 1, 0, 53, 42})
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := DecodeDatagram(b)
		if err == nil {
			_, err = DecodeDatagram(EncodeDatagram(d.SessionID, d.Addr, d.Payload))
			if err != nil {
				t.Fatal(err)
			}
		}
	})
}
