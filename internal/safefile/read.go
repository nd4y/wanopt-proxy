// Package safefile bounds configuration reads and rejects special files.
package safefile

import (
	"errors"
	"io"
)

var ErrSize = errors.New("file exceeds size limit")

func Read(path string, max int64) ([]byte, error) {
	if max < 1 {
		return nil, errors.New("invalid file limit")
	}
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("configuration must be a regular file")
	}
	if st.Size() > max {
		return nil, ErrSize
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if len(b) > int(max) {
		return nil, ErrSize
	}
	return b, err
}
