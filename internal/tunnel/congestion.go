package tunnel

import (
	"github.com/quic-go/quic-go"
)

var bbrConfigurer func(*quic.Config)

func CongestionAvailable(mode string) bool {
	return mode == "" || mode == "reno" || (mode == "bbr" && bbrConfigurer != nil)
}
func configureCongestion(c *quic.Config, mode string) *quic.Config {
	if !CongestionAvailable(mode) {
		panic("tunnel: congestion controller unavailable in this build")
	}
	if mode == "bbr" {
		bbrConfigurer(c)
	}
	return c
}
