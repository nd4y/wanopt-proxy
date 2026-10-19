package config

import (
	"errors"
	"reflect"
	"time"
)

func validateOverlap(value string, expires time.Time) error {
	if value == "" {
		if !expires.IsZero() {
			return errors.New("config: rotation expiry requires alternate credential")
		}
		return nil
	}
	if expires.IsZero() || expires.After(time.Now().Add(7*24*time.Hour)) {
		return errors.New("config: alternate credential needs expiry no more than 7 days ahead")
	}
	return nil
}

// SameRuntimeSettings excludes credential material and certificate paths only.
func (a Server) SameRuntimeSettings(b Server) bool {
	a.PSK = ""
	b.PSK = ""
	a.PreviousPSK = ""
	b.PreviousPSK = ""
	a.PreviousPSKExpires = time.Time{}
	b.PreviousPSKExpires = time.Time{}
	a.CertFile = ""
	b.CertFile = ""
	a.KeyFile = ""
	b.KeyFile = ""
	return reflect.DeepEqual(a, b)
}
