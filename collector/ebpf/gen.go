package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 offcpu bpf/offcpu.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 iolatency bpf/iolatency.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 lockwait bpf/lockwait.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 tcpretrans bpf/tcpretrans.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 netthroughput bpf/netthroughput.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 tcprtt bpf/tcprtt.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 tcpconnlat bpf/tcpconnlat.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 kfreeskb bpf/kfreeskb.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 tcpreset bpf/tcpreset.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 sockstate bpf/sockstate.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 modload bpf/modload.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 oomkill bpf/oomkill.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 directreclaim bpf/directreclaim.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 cgthrottle bpf/cgthrottle.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 runqlat bpf/runqlat.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 wbstall bpf/wbstall.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 pgfault bpf/pgfault.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 swapevict bpf/swapevict.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 syscalldissect bpf/syscalldissect.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 sockio bpf/sockio.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 execsnoop bpf/execsnoop.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 ptracedetect bpf/ptracedetect.c
