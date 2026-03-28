package sessionlatency

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.21.0 -cc clang -cflags "-O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu" probe ./bpf/probe.c
