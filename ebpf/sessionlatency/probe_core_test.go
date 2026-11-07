package sessionlatency

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// TestSchedTracepointContextsAreRelocated checks that the sched programs
// read their tracepoint context through CO-RE relocations, not through
// offsets fixed at compile time. The layout of these contexts differs between
// kernels (RHEL 9 adds a common field; newer kernels store the fork comms as
// __data_loc strings), and a fixed offset that reaches past the context makes
// the kernel refuse to attach the program.
func TestSchedTracepointContextsAreRelocated(t *testing.T) {
	spec, err := loadProbe()
	if err != nil {
		t.Fatalf("loadProbe: %v", err)
	}

	tests := []struct {
		program string
		context string
		// Number of distinct context fields the program reads.
		fields int
	}{
		{program: "trace_sched_process_fork", context: "trace_event_raw_sched_process_fork", fields: 2},
		{program: "trace_sched_process_exec", context: "trace_event_raw_sched_process_exec", fields: 2},
	}
	for _, tt := range tests {
		t.Run(tt.program, func(t *testing.T) {
			prog, ok := spec.Programs[tt.program]
			if !ok {
				t.Fatalf("program %s not found", tt.program)
			}
			relocs := map[string]bool{}
			for i := range prog.Instructions {
				relo := btf.CORERelocationMetadata(&prog.Instructions[i])
				if relo == nil {
					continue
				}
				s := relo.String()
				if strings.Contains(s, `"`+tt.context+`"`) {
					// The string names the relocation kind, the type and
					// the field accessor; one entry per field read.
					relocs[s[:strings.LastIndex(s, ", local_id=")]] = true
				}
			}
			if len(relocs) != tt.fields {
				t.Errorf("%s has CO-RE relocations for %d fields of %s, want %d: %v",
					tt.program, len(relocs), tt.context, tt.fields, relocs)
			}
		})
	}
}
