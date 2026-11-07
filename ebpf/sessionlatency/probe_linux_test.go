//go:build linux

package sessionlatency

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/asm"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"
)

// requireBPFEnv makes the privileged tests fail instead of skip, so that a CI
// step running them with sudo cannot pass by skipping everything.
const requireBPFEnv = "SSH_EXPORTER_REQUIRE_BPF"

// cEventLayout is the layout of struct event in bpf/probe.c as the compiler
// lays it out: ts_ns is aligned to 8 bytes, so 4 bytes of padding follow
// bytes, and the struct is 80 bytes long.
var cEventLayout = struct {
	kind, family, pid, ppid, uid, bytes, tsNs, addr, comm, parentComm, size int
}{
	kind: 0, family: 1, pid: 4, ppid: 8, uid: 12, bytes: 16,
	tsNs: 24, addr: 32, comm: 48, parentComm: 64, size: 80,
}

// TestRawEventMatchesBPFEventSize ties rawEvent to the object that is
// embedded in the binary: every program reserves sizeof(struct event) bytes
// in the ring buffer, and runRingbuf decodes them into a rawEvent.
func TestRawEventMatchesBPFEventSize(t *testing.T) {
	spec, err := loadProbe()
	if err != nil {
		t.Fatalf("loadProbe: %v", err)
	}
	reserve := asm.FnRingbufReserve.Call()
	want := binary.Size(rawEvent{})

	checked := 0
	for name, prog := range spec.Programs {
		var size int64 = -1
		for _, ins := range prog.Instructions {
			if ins.OpCode.Class().IsALU() && ins.OpCode.ALUOp() == asm.Mov &&
				ins.OpCode.Source() == asm.ImmSource && ins.Dst == asm.R2 {
				size = ins.Constant
				continue
			}
			if !ins.IsBuiltinCall() || ins.Constant != reserve.Constant {
				continue
			}
			if size < 0 {
				t.Fatalf("%s: cannot find the constant size passed to bpf_ringbuf_reserve", name)
			}
			if int(size) != want {
				t.Errorf("%s reserves %d bytes per event, but rawEvent decodes %d bytes", name, size, want)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no program calls bpf_ringbuf_reserve")
	}
}

// TestRawEventDecodesCEventLayout decodes a sample laid out like struct event
// the way runRingbuf does, and checks that every field lands where the BPF
// program wrote it.
func TestRawEventDecodesCEventLayout(t *testing.T) {
	l := cEventLayout
	sample := make([]byte, l.size)
	sample[l.kind] = byte(traceEventExec)
	sample[l.family] = unix.AF_INET
	binary.LittleEndian.PutUint32(sample[l.pid:], 4242)
	binary.LittleEndian.PutUint32(sample[l.ppid:], 4241)
	binary.LittleEndian.PutUint32(sample[l.uid:], 1001)
	binary.LittleEndian.PutUint32(sample[l.bytes:], 37)
	binary.LittleEndian.PutUint64(sample[l.tsNs:], 123_456_789_000)
	copy(sample[l.addr:], []byte{192, 0, 2, 10})
	copy(sample[l.comm:], "/usr/bin/bash")
	copy(sample[l.parentComm:], "sshd")

	var raw rawEvent
	if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if raw.TSNs != 123_456_789_000 {
		t.Errorf("TSNs = %d, want 123456789000", raw.TSNs)
	}

	base := time.Unix(1_700_000_000, 0)
	p := &Probe{conv: monotonicConverter{baseMonoNs: 0, baseWall: base}}
	got := p.convertRawEvent(raw)
	want := traceEvent{
		Kind:       traceEventExec,
		PID:        4242,
		ParentPID:  4241,
		UID:        1001,
		Comm:       "/usr/bin/bash",
		ParentComm: "sshd",
		RemoteIP:   "192.0.2.10",
		Bytes:      37,
		Timestamp:  base.Add(123_456_789_000 * time.Nanosecond),
	}
	if got != want {
		t.Errorf("convertRawEvent:\n got  %+v\n want %+v", got, want)
	}
}

// TestProbeLoadAndAttach loads the embedded objects through the kernel
// verifier and attaches them, which needs root (CAP_BPF and CAP_PERFMON) and
// tracefs. CI runs it with sudo and SSH_EXPORTER_REQUIRE_BPF=1.
func TestProbeLoadAndAttach(t *testing.T) {
	skipUnlessBPF(t)

	t.Run("load", func(t *testing.T) {
		var objs probeObjects
		if err := loadProbeObjects(&objs, nil); err != nil {
			if errors.Is(err, unix.EPERM) {
				skipOrFail(t, "loading BPF programs is not permitted here: %v", err)
			}
			t.Fatalf("load bpf objects: %v", err)
		}
		if err := objs.Close(); err != nil {
			t.Errorf("close bpf objects: %v", err)
		}
	})

	t.Run("attach", func(t *testing.T) {
		if !tracefsMounted() {
			skipOrFail(t, "tracefs is not mounted")
		}
		reg := prometheus.NewPedanticRegistry()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		probe, err := Start(ctx, reg, slog.Default(), Options{Timeout: time.Second})
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		if got := testutil.ToFloat64(probe.processor.up); got != 1 {
			t.Errorf("ssh_exporter_ebpf_shell_usable_up = %v after Start, want 1", got)
		}

		// Cancelling ctx closes the probe; Close waits for that to finish.
		cancel()
		probe.Close()
		if got := testutil.ToFloat64(probe.processor.up); got != 0 {
			t.Errorf("ssh_exporter_ebpf_shell_usable_up = %v after Close, want 0", got)
		}
	})
}

func skipUnlessBPF(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		skipOrFail(t, "needs root to load BPF programs")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		skipOrFail(t, "kernel BTF is not available: %v", err)
	}
}

func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv(requireBPFEnv) != "" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

func tracefsMounted() bool {
	for _, dir := range []string{"/sys/kernel/tracing/events", "/sys/kernel/debug/tracing/events"} {
		if _, err := os.Stat(dir); err == nil {
			return true
		}
	}
	return false
}
