//go:build linux

package phpfpm

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// /proc/<pid>/io exposes rchar/wchar (incl. tmpfs, page cache — what
// matters for PHP workload visibility since most PHP I/O is reading
// cached code/template files).

type ioSample struct {
	rchar, wchar uint64
	at           time.Time
}

var (
	ioMu      sync.Mutex
	ioSamples = map[int]ioSample{}
)

// joinLiveIO fills DiskReadBps + DiskWriteBps on each worker.
func joinLiveIO(workers []model.PHPFPMWorker) {
	now := time.Now()
	ioMu.Lock()
	defer ioMu.Unlock()

	live := map[int]struct{}{}
	for i := range workers {
		pid := workers[i].PID
		live[pid] = struct{}{}
		rc, wc := readProcIO(pid)
		if rc == 0 && wc == 0 {
			continue
		}
		if prev, ok := ioSamples[pid]; ok {
			dt := now.Sub(prev.at).Seconds()
			if dt > 0 {
				if rc >= prev.rchar {
					workers[i].DiskReadBps = float64(rc-prev.rchar) / dt
				}
				if wc >= prev.wchar {
					workers[i].DiskWriteBps = float64(wc-prev.wchar) / dt
				}
			}
		}
		ioSamples[pid] = ioSample{rchar: rc, wchar: wc, at: now}
	}
	for pid := range ioSamples {
		if _, ok := live[pid]; !ok {
			delete(ioSamples, pid)
		}
	}
}

func readProcIO(pid int) (rchar, wchar uint64) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/io")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		v := strings.TrimSpace(line[i+1:])
		switch k {
		case "rchar":
			rchar, _ = strconv.ParseUint(v, 10, 64)
		case "wchar":
			wchar, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	return rchar, wchar
}
