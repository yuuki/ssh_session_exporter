package authlog

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// FileWatcher tails an auth log file and emits parsed SSH failure events.
type FileWatcher struct {
	path   string
	events chan AuthEvent
	logger *slog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewFileWatcher(path string, logger *slog.Logger) *FileWatcher {
	return &FileWatcher{
		path:   path,
		events: make(chan AuthEvent, 256),
		logger: logger,
	}
}

func (w *FileWatcher) Events() <-chan AuthEvent {
	return w.events
}

// Start begins tailing the auth log file from the current end of file,
// handling log rotation when the file shrinks.
// The file is opened and seeked synchronously before Start returns,
// so any writes after Start returns will be captured by the watcher.
func (w *FileWatcher) Start(ctx context.Context) error {
	f, err := os.Open(w.path)
	if err != nil {
		return err
	}
	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		f.Close()
		return err
	}

	ctx, w.cancel = context.WithCancel(ctx)
	w.wg.Add(1)
	go w.run(ctx, f, offset)
	return nil
}

func (w *FileWatcher) run(ctx context.Context, f *os.File, offset int64) {
	defer w.wg.Done()
	defer close(w.events)
	defer f.Close()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var partial string

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fi, statErr := os.Stat(w.path)
			if statErr != nil {
				w.logger.Warn("stat file", "error", statErr)
				continue
			}
			if fi.Size() < offset {
				// Log rotation detected: re-open from the beginning.
				f.Close()
				var err error
				f, err = os.Open(w.path)
				if err != nil {
					w.logger.Warn("reopen file", "error", err)
					continue
				}
				offset = 0
				partial = ""
			}

			buf := make([]byte, 32*1024)
			n, readErr := f.Read(buf)
			if n > 0 {
				offset += int64(n)
				lines, remainder := splitLines(partial + string(buf[:n]))
				partial = remainder
				for _, line := range lines {
					event := ParseLine(line)
					if event == nil {
						continue
					}
					select {
					case w.events <- *event:
					case <-ctx.Done():
						return
					}
				}
			}
			if readErr != nil && readErr != io.EOF {
				w.logger.Warn("read error", "error", readErr)
			}
		}
	}
}

// splitLines returns complete lines and the remaining partial line.
func splitLines(text string) (lines []string, partial string) {
	parts := strings.Split(text, "\n")
	if len(parts) == 1 {
		return nil, parts[0]
	}
	return parts[:len(parts)-1], parts[len(parts)-1]
}

func (w *FileWatcher) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	w.wg.Wait()
}
