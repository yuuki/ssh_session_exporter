package authlog

import (
	"context"
	"io"
	"log/slog"

	"github.com/nxadm/tail"
)

// Watcher watches an auth log file for SSH events.
type Watcher interface {
	Events() <-chan AuthEvent
	Start(ctx context.Context) error
	Stop()
}

// FileWatcher tails an auth log file and emits parsed SSH events.
type FileWatcher struct {
	path   string
	events chan AuthEvent
	tail   *tail.Tail
	logger *slog.Logger
	cancel context.CancelFunc
}

// NewFileWatcher creates a new FileWatcher for the given auth log path.
func NewFileWatcher(path string, logger *slog.Logger) *FileWatcher {
	return &FileWatcher{
		path:   path,
		events: make(chan AuthEvent, 256),
		logger: logger,
	}
}

// Events returns the channel of parsed auth events.
func (w *FileWatcher) Events() <-chan AuthEvent {
	return w.events
}

// Start begins tailing the auth log file. It reads from the end of the file
// and follows new lines, handling log rotation via ReOpen.
func (w *FileWatcher) Start(ctx context.Context) error {
	ctx, w.cancel = context.WithCancel(ctx)

	t, err := tail.TailFile(w.path, tail.Config{
		Follow:    true,
		ReOpen:    true,
		Poll:      true,
		Location:  &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd},
		MustExist: true,
		Logger:    tail.DiscardingLogger,
	})
	if err != nil {
		return err
	}
	w.tail = t

	go w.run(ctx)
	return nil
}

func (w *FileWatcher) run(ctx context.Context) {
	defer close(w.events)

	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-w.tail.Lines:
			if !ok {
				return
			}
			if line.Err != nil {
				w.logger.Warn("tail error", "error", line.Err)
				continue
			}
			event := ParseLine(line.Text)
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
}

// Stop stops tailing the auth log file.
func (w *FileWatcher) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	if w.tail != nil {
		w.tail.Stop()
		w.tail.Cleanup()
	}
}
