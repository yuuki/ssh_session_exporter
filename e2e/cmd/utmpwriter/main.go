//go:build linux

package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"unsafe"
)

const (
	userProcess int16 = 7
	utNameSize        = 32
	utLineSize        = 32
	utHostSize        = 256
	utIDSize          = 4
)

// rawRecord mirrors the Linux utmp struct (384 bytes on x86_64).
// Must match utmp/utmp.go exactly.
type rawRecord struct {
	Type    int16
	_       [2]byte // padding for alignment
	PID     int32
	Line    [utLineSize]byte
	ID      [utIDSize]byte
	User    [utNameSize]byte
	Host    [utHostSize]byte
	ExitT   int16
	ExitE   int16
	Session int32
	TvSec   int32
	TvUsec  int32
	AddrV6  [4]int32
	_       [20]byte // unused
}

func init() {
	if unsafe.Sizeof(rawRecord{}) != 384 {
		panic(fmt.Sprintf("rawRecord size is %d, expected 384", unsafe.Sizeof(rawRecord{})))
	}
}

type sessionSpec struct {
	User  string `json:"user"`
	TTY   string `json:"tty"`
	Host  string `json:"host"`
	PID   int32  `json:"pid"`
	TvSec int32  `json:"tv_sec"`
}

func main() {
	path := flag.String("path", "/data/utmp", "Path to the utmp file to write")
	action := flag.String("action", "write", "Action: write or clear")
	flag.Parse()

	switch *action {
	case "write":
		if err := writeRecords(*path); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			os.Exit(1)
		}
	case "clear":
		if err := os.Truncate(*path, 0); err != nil {
			fmt.Fprintf(os.Stderr, "clear: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown action: %s\n", *action)
		os.Exit(1)
	}
}

func writeRecords(path string) error {
	var specs []sessionSpec
	if err := json.NewDecoder(os.Stdin).Decode(&specs); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	for _, s := range specs {
		var rec rawRecord
		rec.Type = userProcess
		rec.PID = s.PID
		rec.TvSec = s.TvSec
		copyString(rec.User[:], s.User)
		copyString(rec.Line[:], s.TTY)
		copyString(rec.Host[:], s.Host)

		if err := binary.Write(f, binary.LittleEndian, &rec); err != nil {
			return fmt.Errorf("write record: %w", err)
		}
	}

	return nil
}

func copyString(dst []byte, src string) {
	copy(dst, src)
	if len(src) < len(dst) {
		dst[len(src)] = 0
	}
}
