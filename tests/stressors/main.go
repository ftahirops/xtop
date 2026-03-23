// Standalone stressor that appears with its own binary name in /proc/PID/comm.
// No dependency on stress-ng. Each stress type is pure Go.
//
// Usage: go build -o <random-name> . && ./<random-name> --type cpu --duration 45s
//        go build -o <random-name> . && ./<random-name> --type mem --bytes 12G --duration 45s
//        go build -o <random-name> . && ./<random-name> --type io --duration 45s
package main

import (
	"flag"
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	stressType := flag.String("type", "cpu", "stress type: cpu, mem, io, iorand, net, ctxswitch, mixed")
	duration := flag.Duration("duration", 45*time.Second, "how long to stress")
	workers := flag.Int("workers", 0, "number of workers (0=auto)")
	memBytes := flag.String("bytes", "1G", "memory to allocate (for mem type)")
	flag.Parse()

	if *workers <= 0 {
		*workers = runtime.NumCPU()
	}

	fmt.Printf("stressor: type=%s workers=%d duration=%s\n", *stressType, *workers, *duration)

	done := make(chan struct{})
	go func() {
		time.Sleep(*duration)
		close(done)
	}()

	switch *stressType {
	case "cpu":
		stressCPU(*workers, done)
	case "mem":
		stressMem(*memBytes, done)
	case "io":
		stressIO(*workers, done)
	case "iorand":
		stressIORand(*workers, done)
	case "net":
		stressNet(*workers, done)
	case "ctxswitch":
		stressCtxSwitch(*workers, done)
	case "mixed":
		stressMixed(*workers, *memBytes, done)
	default:
		fmt.Fprintf(os.Stderr, "unknown type: %s\n", *stressType)
		os.Exit(1)
	}
	fmt.Println("stressor: done")
}

func stressCPU(n int, done chan struct{}) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x := 1.0
			for {
				select {
				case <-done:
					return
				default:
					// Burn CPU with math
					for j := 0; j < 10000; j++ {
						x = math.Sin(x)*math.Cos(x) + math.Sqrt(math.Abs(x)+1)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func parseBytes(s string) int64 {
	s = strings.TrimSpace(strings.ToUpper(s))
	multiplier := int64(1)
	if strings.HasSuffix(s, "G") {
		multiplier = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "M") {
		multiplier = 1024 * 1024
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "K") {
		multiplier = 1024
		s = s[:len(s)-1]
	}
	n, _ := strconv.ParseInt(s, 10, 64)
	return n * multiplier
}

func stressMem(bytesStr string, done chan struct{}) {
	total := parseBytes(bytesStr)
	if total <= 0 {
		total = 1024 * 1024 * 1024 // 1G default
	}

	// Allocate in 64MB chunks to avoid single huge allocation
	chunkSize := int64(64 * 1024 * 1024)
	nChunks := int(total / chunkSize)
	if nChunks < 1 {
		nChunks = 1
	}

	fmt.Printf("stressor: allocating %d chunks of 64MB = %dMB total\n", nChunks, nChunks*64)

	chunks := make([][]byte, 0, nChunks)
	for i := 0; i < nChunks; i++ {
		select {
		case <-done:
			return
		default:
		}
		chunk := make([]byte, chunkSize)
		// Touch every page to force physical allocation
		for j := 0; j < len(chunk); j += 4096 {
			chunk[j] = byte(i + j)
		}
		chunks = append(chunks, chunk)
	}

	fmt.Printf("stressor: allocated %dMB, holding...\n", len(chunks)*64)

	// Keep touching memory to prevent swap-out
	for {
		select {
		case <-done:
			return
		default:
			for _, chunk := range chunks {
				for j := 0; j < len(chunk); j += 4096 {
					chunk[j]++
				}
			}
		}
	}
}

func stressIO(n int, done chan struct{}) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			path := fmt.Sprintf("/tmp/stressor-io-%d-%d", os.Getpid(), id)
			defer os.Remove(path)

			buf := make([]byte, 1024*1024) // 1MB writes
			rand.Read(buf)

			for {
				select {
				case <-done:
					return
				default:
				}
				f, err := os.Create(path)
				if err != nil {
					continue
				}
				for j := 0; j < 100; j++ {
					f.Write(buf)
				}
				f.Sync()
				f.Close()
			}
		}(i)
	}
	wg.Wait()
}

func stressIORand(n int, done chan struct{}) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			path := fmt.Sprintf("/tmp/stressor-iorand-%d-%d", os.Getpid(), id)
			defer os.Remove(path)

			// Create file
			f, err := os.Create(path)
			if err != nil {
				return
			}
			// Pre-allocate 256MB
			f.Truncate(256 * 1024 * 1024)

			buf := make([]byte, 4096) // 4K random writes
			rand.Read(buf)

			for {
				select {
				case <-done:
					f.Close()
					return
				default:
				}
				offset := rand.Int63n(256 * 1024 * 1024)
				f.WriteAt(buf, offset)
				f.Sync()
			}
		}(i)
	}
	wg.Wait()
}

func stressNet(n int, done chan struct{}) {
	// Create and destroy TCP connections rapidly
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				conn, err := net.DialTimeout("tcp", "127.0.0.1:80", 50*time.Millisecond)
				if err == nil {
					conn.Close()
				}
				// Also try nonexistent ports to generate errors
				conn2, err := net.DialTimeout("tcp", "127.0.0.1:1", 10*time.Millisecond)
				if err == nil {
					conn2.Close()
				}
			}
		}()
	}
	wg.Wait()
}

func stressCtxSwitch(n int, done chan struct{}) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					runtime.Gosched() // yield to trigger context switches
				}
			}
		}()
	}
	wg.Wait()
}

func stressMixed(n int, memStr string, done chan struct{}) {
	// Run CPU + mem + IO concurrently
	var wg sync.WaitGroup

	// CPU workers
	cpuN := n / 3
	if cpuN < 1 {
		cpuN = 1
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		stressCPU(cpuN, done)
	}()

	// Memory
	wg.Add(1)
	go func() {
		defer wg.Done()
		stressMem(memStr, done)
	}()

	// IO
	ioN := n / 3
	if ioN < 1 {
		ioN = 1
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		stressIO(ioN, done)
	}()

	wg.Wait()
}
