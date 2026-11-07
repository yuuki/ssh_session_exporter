package utmp

import (
	"fmt"
	"testing"
)

// Every scrape parses the whole utmp file.
func BenchmarkParseRecords(b *testing.B) {
	var data []byte
	for i := range int32(64) {
		data = append(data, makeNativeRecord(userProcess, 1000+i, "alice", fmt.Sprintf("pts/%d", i), "192.0.2.1", 1700000000+i)...)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := parseRecords(data); err != nil {
			b.Fatal(err)
		}
	}
}
