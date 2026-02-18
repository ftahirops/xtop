package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 offcpu bpf/offcpu.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 iolatency bpf/iolatency.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 lockwait bpf/lockwait.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 tcpretrans bpf/tcpretrans.c
