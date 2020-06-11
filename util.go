package socks5

import (
	"context"
	"io"
)

func readSingleByte(r io.Reader) (byte, error) {
	b := []byte{0}
	_, err := io.ReadFull(r, b)
	return b[0], err
}

func pipe(ctx context.Context,
	conn io.ReadWriter, target io.ReadWriter) (err error) {
	errCh := make(chan error, 2)
	go func() {
		_, e := io.Copy(conn, target)
		errCh <- e
	}()
	go func() {
		_, e := io.Copy(target, conn)
		errCh <- e
	}()

	select {
	case err = <-errCh:
	case <-ctx.Done():
		err = ctx.Err()
	}
	return
}
