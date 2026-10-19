//go:build !unix

package safefile

import (
	"errors"
	"os"
)

func openRegular(path string) (*os.File, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("configuration must be a regular file")
	}
	return os.Open(path)
}
