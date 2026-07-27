package logwatch

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"time"
)

type Tailer struct {
	Path       string
	PollEvery  time.Duration
	StartAtEnd bool
}

func (t Tailer) Follow(ctx context.Context, lines chan<- string) error {
	if t.Path == "" {
		return errors.New("tail path is required")
	}
	poll := t.PollEvery
	if poll <= 0 {
		poll = time.Second
	}

	var offset int64
	var previous os.FileInfo
	if t.StartAtEnd {
		if st, err := os.Stat(t.Path); err == nil {
			offset = st.Size()
			previous = st
		}
	}

	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		next, current, err := t.readFrom(ctx, offset, previous, lines)
		if err == nil {
			offset = next
			previous = current
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (t Tailer) readFrom(ctx context.Context, offset int64, previous os.FileInfo, lines chan<- string) (int64, os.FileInfo, error) {
	file, err := os.Open(t.Path)
	if err != nil {
		return offset, previous, err
	}
	defer file.Close()

	st, err := file.Stat()
	if err != nil {
		return offset, previous, err
	}
	if previous != nil && !os.SameFile(previous, st) {
		offset = 0
	}
	if st.Size() < offset {
		offset = 0
	} else if offset > 0 {
		ok, err := isLineBoundary(file, offset)
		if err != nil {
			return offset, st, err
		}
		if !ok {
			offset = 0
		}
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return offset, st, err
	}

	reader := bufio.NewReader(file)
	position := offset
	for {
		line, err := reader.ReadString('\n')
		if err == nil {
			select {
			case lines <- line:
				position += int64(len(line))
			case <-ctx.Done():
				return position, st, ctx.Err()
			}
		}
		if errors.Is(err, io.EOF) {
			return position, st, nil
		}
		if err != nil {
			return position, st, err
		}
	}
}

func isLineBoundary(file *os.File, offset int64) (bool, error) {
	if _, err := file.Seek(offset-1, io.SeekStart); err != nil {
		return false, err
	}
	var previous [1]byte
	n, err := file.Read(previous[:])
	if err != nil {
		return false, err
	}
	return n == 1 && previous[0] == '\n', nil
}
