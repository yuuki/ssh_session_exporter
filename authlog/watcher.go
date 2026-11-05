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

	buf := make([]byte, 32*1024)
	tail := tailState{f: f, offset: offset}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !w.poll(ctx, &tail, buf) {
				return
			}
		}
	}
}

// tailState is what the watcher carries from one poll to the next.
type tailState struct {
	f       *os.File
	offset  int64
	partial string // text after the last newline, completed by a later read
}

// poll reads what was appended since the previous tick and emits its events.
// It reports false when the watcher has to stop.
func (w *FileWatcher) poll(ctx context.Context, tail *tailState, buf []byte) bool {
	n, readErr := tail.f.Read(buf)
	if n > 0 {
		tail.offset += int64(n)
		lines, remainder := splitLines(tail.partial + string(buf[:n]))
		tail.partial = remainder
		if !w.emitLines(ctx, lines) {
			return false
		}
	}
	if readErr != nil && readErr != io.EOF {
		w.logger.Warn("read error", "error", readErr)
	}

	// Check for log rotation only when at EOF (no new data).
	if n == 0 {
		return w.reopenIfRotated(tail)
	}
	return true
}

// emitLines sends the events of the recognised lines in order. It reports
// false when ctx ends while the consumer is not keeping up.
func (w *FileWatcher) emitLines(ctx context.Context, lines []string) bool {
	for _, line := range lines {
		event := ParseLine(line)
		if event == nil {
			continue
		}
		select {
		case w.events <- *event:
		case <-ctx.Done():
			return false
		}
	}
	return true
}

// reopenIfRotated treats a file at w.path that is smaller than what has been
// read as a rotated log and restarts from its beginning. A missing file is
// waited for. It reports false when the new file cannot be opened.
func (w *FileWatcher) reopenIfRotated(tail *tailState) bool {
	fi, statErr := os.Stat(w.path)
	if statErr != nil || fi.Size() >= tail.offset {
		return true
	}

	tail.f.Close()
	f, err := os.Open(w.path)
	if err != nil {
		w.logger.Warn("reopen file", "error", err)
		return false
	}
	tail.f = f
	tail.offset = 0
	tail.partial = ""
	return true
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
