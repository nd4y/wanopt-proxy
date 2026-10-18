package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRotationAndGlobalLimitValidation(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	for _, suffix := range []string{"max_active_streams: -1\n", "max_active_streams: 1\nmax_compressed_streams: 2\n", "congestion_control: turbo\n", "previous_psk: " + key + "\n", "previous_psk_expires: '2020-01-01T00:00:00Z'\n", fmt.Sprintf("previous_psk: %s\nprevious_psk_expires: '%s'\n", key, time.Now().Add(30*24*time.Hour).Format(time.RFC3339))} {
		if _, err := LoadServer(configFile(t, testPSK()+"allow_ephemeral_cert: true\n"+suffix)); err == nil {
			t.Fatalf("accepted invalid setting %q", suffix)
		}
	}
	valid := fmt.Sprintf("previous_psk: %s\nprevious_psk_expires: '%s'\n", key, time.Now().Add(time.Hour).Format(time.RFC3339))
	if _, err := LoadServer(configFile(t, testPSK()+"allow_ephemeral_cert: true\n"+valid)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClient(configFile(t, testClient()+strings.ReplaceAll(valid, "previous_psk", "next_pin"))); err != nil {
		t.Fatal(err)
	}
	a := Server{PSK: "a", MaxActiveStreams: 4}
	b := a
	b.PSK = "b"
	b.CertFile = "rotated.pem"
	if !a.SameRuntimeSettings(b) {
		t.Fatal("credential-only reload rejected")
	}
	b.MaxActiveStreams = 5
	if a.SameRuntimeSettings(b) {
		t.Fatal("runtime change allowed during credential reload")
	}
}
