//go:build linux

package collector

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/yuuki/ssh_session_exporter/sessiontracker"
	"github.com/yuuki/ssh_session_exporter/utmp"
)

// Offsets in the 384-byte utmp record (see utmp/parser.go).
const (
	utmpRecordSize = 384
	utmpLineOff    = 8
	utmpUserOff    = 44
	utmpHostOff    = 76
	utmpUserProc   = 7
)

func utmpRecord(user, line, host string) []byte {
	rec := make([]byte, utmpRecordSize)
	binary.LittleEndian.PutUint16(rec, utmpUserProc)
	copy(rec[utmpLineOff:utmpLineOff+32], line)
	copy(rec[utmpUserOff:utmpUserOff+32], user)
	copy(rec[utmpHostOff:utmpHostOff+256], host)
	return rec
}

// FuzzCollectUtmpRecord scrapes a utmp file holding one login record with
// arbitrary contents through the real FileReader. utmp is not only written
// by sshd (libutempter lets local users record a host of their choice), and
// a scrape that fails costs every metric of the exporter.
func FuzzCollectUtmpRecord(f *testing.F) {
	f.Add(utmpRecord("alice", "pts/0", "192.168.1.10"))
	f.Add(utmpRecord("al\xffice", "pts/\xfe0", "192.168.\x801.10"))
	f.Add(utmpRecord("bob", "pts/1", ""))
	path := filepath.Join(f.TempDir(), "utmp")

	f.Fuzz(func(t *testing.T, rec []byte) {
		// One USER_PROCESS record; the fuzzer chooses every other byte.
		buf := make([]byte, utmpRecordSize)
		copy(buf, rec)
		binary.LittleEndian.PutUint16(buf, utmpUserProc)
		if err := os.WriteFile(path, buf, 0o600); err != nil {
			t.Fatalf("write utmp: %v", err)
		}

		reg := prometheus.NewPedanticRegistry()
		_, err := New(reg, utmp.NewFileReader(path, discardLogger), sessiontracker.New(discardLogger), discardLogger)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		families, err := reg.Gather()
		if err != nil {
			t.Fatalf("scrape failed: %v", err)
		}
		for _, mf := range families {
			if mf.GetName() == "ssh_exporter_scrape_success" {
				if got := mf.GetMetric()[0].GetGauge().GetValue(); got != 1 {
					t.Fatalf("ssh_exporter_scrape_success = %v, want 1", got)
				}
				return
			}
		}
		t.Fatal("ssh_exporter_scrape_success is missing")
	})
}
