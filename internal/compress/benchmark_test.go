package compress

import (
	"bytes"
	"io"
	"testing"
)

func BenchmarkBlockCodec(b *testing.B) {
	for _, kind := range []string{"text", "random"} {
		data := randomData(1 << 20)
		if kind == "text" {
			data = bytes.Repeat([]byte("service=api method=GET path=/v1/items status=200 duration_ms=42\n"), 18000)
		}
		var encoded bytes.Buffer
		if _, err := Copy(&encoded, bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
		wire := encoded.Bytes()
		for _, decode := range []bool{false, true} {
			name := "encode"
			if decode {
				name = "decode"
			}
			b.Run(kind+"/"+name, func(b *testing.B) {
				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					var err error
					if decode {
						_, err = Decopy(io.Discard, bytes.NewReader(wire))
					} else {
						_, err = Copy(io.Discard, bytes.NewReader(data))
					}
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
