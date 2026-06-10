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
	PollEvery time.Duration
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
	if t.StartAtEnd {
		if st, err := os.Stat(t.Path); err == nil {
			offset = st.Size()
		}
	}

	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		next, err := t.readFrom(offset, lines)
		if err == nil {
			offset = next
		} else if errors.Is(err, errTruncated) {
			offset = 0
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

var errTruncated = errors.New("file truncated")

func (t Tailer) readFrom(offset int64, lines chan<- string) (int64, error) {
	file, err := os.Open(t.Path)
	if err != nil {
		return offset, err
	}
	defer file.Close()

	st, err := file.Stat()
	if err != nil {
		return offset, err
	}
	if st.Size() < offset {
		return offset, errTruncated
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return offset, err
	}

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			lines <- line
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return offset, err
		}
	}
	pos, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return offset, err
	}
	return pos, nil
}
