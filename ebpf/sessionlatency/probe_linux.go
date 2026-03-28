//go:build linux

package sessionlatency

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/yuuki/ssh_session_exporter/authlog"
	"golang.org/x/sys/unix"
)

const cleanupInterval = 5 * time.Second

type Probe struct {
	logger    *slog.Logger
	processor *processor
	reader    *ringbuf.Reader
	links     []link.Link
	objects   probeObjects
	conv      monotonicConverter

	wg        sync.WaitGroup
	closeOnce sync.Once
}

type rawEvent struct {
	Kind       uint8
	Family     uint8
	Pad        uint16
	PID        uint32
	PPID       uint32
	UID        uint32
	Bytes      uint32
	TSNs       uint64
	Addr       [16]byte
	Comm       [16]byte
	ParentComm [16]byte
}

type monotonicConverter struct {
	baseMonoNs int64
	baseWall   time.Time
}

func newMonotonicConverter() (monotonicConverter, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return monotonicConverter{}, err
	}
	return monotonicConverter{
		baseMonoNs: ts.Nano(),
		baseWall:   time.Now(),
	}, nil
}

func (c monotonicConverter) Time(ns uint64) time.Time {
	return c.baseWall.Add(time.Duration(int64(ns) - c.baseMonoNs))
}

func Start(ctx context.Context, reg prometheus.Registerer, logger *slog.Logger, opts Options) (*Probe, error) {
	processor, err := newProcessor(reg, logger, opts)
	if err != nil {
		return nil, err
	}

	probe := &Probe{
		logger:    logger,
		processor: processor,
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	conv, err := newMonotonicConverter()
	if err != nil {
		return nil, fmt.Errorf("clock_gettime: %w", err)
	}
	probe.conv = conv

	if err := loadProbeObjects(&probe.objects, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	reader, err := ringbuf.NewReader(probe.objects.Events)
	if err != nil {
		probe.objects.Close()
		return nil, fmt.Errorf("create ringbuf reader: %w", err)
	}
	probe.reader = reader

	attachPoints := []struct {
		group string
		name  string
		prog  *ebpf.Program
	}{
		{"syscalls", "sys_enter_accept4", probe.objects.TraceEnterAccept4},
		{"syscalls", "sys_exit_accept4", probe.objects.TraceExitAccept4},
		{"sched", "sched_process_fork", probe.objects.TraceSchedProcessFork},
		{"sched", "sched_process_exec", probe.objects.TraceSchedProcessExec},
		{"sched", "sched_process_exit", probe.objects.TraceSchedProcessExit},
	}
	for _, tp := range attachPoints {
		l, err := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if err != nil {
			probe.Close()
			return nil, fmt.Errorf("attach %s/%s: %w", tp.group, tp.name, err)
		}
		probe.links = append(probe.links, l)
	}
	if err := probe.attachWriteEvent(); err != nil {
		probe.Close()
		return nil, err
	}

	probe.processor.setUp(true)
	probe.wg.Add(2)
	go probe.runRingbuf()
	go probe.runCleanup(ctx)
	go func() {
		<-ctx.Done()
		probe.Close()
	}()

	return probe, nil
}

func (p *Probe) attachWriteEvent() error {
	if l, err := link.Tracepoint("tty", "tty_write", p.objects.TraceTtyWrite, nil); err == nil {
		p.links = append(p.links, l)
		return nil
	}

	enter, err := link.Tracepoint("syscalls", "sys_enter_write", p.objects.TraceEnterWrite, nil)
	if err != nil {
		return fmt.Errorf("attach tty/tty_write fallback sys_enter_write: %w", err)
	}
	exit, err := link.Tracepoint("syscalls", "sys_exit_write", p.objects.TraceExitWrite, nil)
	if err != nil {
		_ = enter.Close()
		return fmt.Errorf("attach tty/tty_write fallback sys_exit_write: %w", err)
	}
	enterv, err := link.Tracepoint("syscalls", "sys_enter_writev", p.objects.TraceEnterWritev, nil)
	if err != nil {
		_ = enter.Close()
		_ = exit.Close()
		return fmt.Errorf("attach tty/tty_write fallback sys_enter_writev: %w", err)
	}
	exitv, err := link.Tracepoint("syscalls", "sys_exit_writev", p.objects.TraceExitWritev, nil)
	if err != nil {
		_ = enter.Close()
		_ = exit.Close()
		_ = enterv.Close()
		return fmt.Errorf("attach tty/tty_write fallback sys_exit_writev: %w", err)
	}
	p.links = append(p.links, enter, exit, enterv, exitv)
	p.logger.Info("tty/tty_write tracepoint unavailable, falling back to syscalls/sys_exit_write")
	return nil
}

func (p *Probe) HandleAuthEvent(event authlog.AuthEvent) {
	p.processor.HandleAuthEvent(event)
}

func (p *Probe) Close() {
	p.closeOnce.Do(func() {
		p.processor.setUp(false)
		if p.reader != nil {
			_ = p.reader.Close()
		}
		for _, l := range p.links {
			_ = l.Close()
		}
		p.objects.Close()
		p.wg.Wait()
	})
}

func (p *Probe) runCleanup(ctx context.Context) {
	defer p.wg.Done()

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.processor.cleanupExpired()
		}
	}
}

func (p *Probe) runRingbuf() {
	defer p.wg.Done()
	var raw rawEvent
	br := bytes.NewReader(nil)
	for {
		record, err := p.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			p.processor.failures.WithLabelValues(failureEventsDropped).Inc()
			p.logger.Warn("failed to read eBPF ringbuf", "error", err)
			continue
		}

		br.Reset(record.RawSample)
		if err := binary.Read(br, binary.LittleEndian, &raw); err != nil {
			p.processor.failures.WithLabelValues(failureEventsDropped).Inc()
			p.logger.Warn("failed to decode eBPF event", "error", err)
			continue
		}
		p.processor.handleTraceEvent(p.convertRawEvent(raw))
	}
}

func (p *Probe) convertRawEvent(raw rawEvent) traceEvent {
	return traceEvent{
		Kind:       traceEventKind(raw.Kind),
		PID:        int32(raw.PID),
		ParentPID:  int32(raw.PPID),
		UID:        raw.UID,
		Comm:       cString(raw.Comm[:]),
		ParentComm: cString(raw.ParentComm[:]),
		RemoteIP:   decodeAddr(raw.Family, raw.Addr),
		Bytes:      raw.Bytes,
		Timestamp:  p.conv.Time(raw.TSNs),
	}
}

func cString(buf []byte) string {
	if i := bytes.IndexByte(buf, 0); i >= 0 {
		buf = buf[:i]
	}
	return string(buf)
}

func decodeAddr(family uint8, addr [16]byte) string {
	switch family {
	case unix.AF_INET:
		a := netip.AddrFrom4([4]byte{addr[0], addr[1], addr[2], addr[3]})
		return a.String()
	case unix.AF_INET6:
		a := netip.AddrFrom16(addr)
		return a.String()
	default:
		return ""
	}
}
