package engine

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// MetricsStore holds the latest snapshot for exporters.
type MetricsStore struct {
	mu     sync.RWMutex
	snap   *model.Snapshot
	rates  *model.RateSnapshot
	result *model.AnalysisResult
	ts     time.Time
}

// NewMetricsStore creates a new store.
func NewMetricsStore() *MetricsStore {
	return &MetricsStore{}
}

// Update stores the latest sample.
func (s *MetricsStore) Update(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) {
	s.mu.Lock()
	s.snap = snap
	s.rates = rates
	s.result = result
	s.ts = time.Now()
	s.mu.Unlock()
}

// Snapshot returns the latest stored sample.
func (s *MetricsStore) Snapshot() (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult, time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap, s.rates, s.result, s.ts
}

// Handler exposes Prometheus metrics for the latest sample.
func (s *MetricsStore) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		snap, rates, result, _ := s.Snapshot()
		if snap == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("# no data yet\n"))
			return
		}
		writePrometheus(w, snap, rates, result)
	})
}

// instrumentedTicker updates a metrics store on each tick.
type instrumentedTicker struct {
	inner Ticker
	store *MetricsStore
}

// NewInstrumentedTicker wraps a ticker and updates the metrics store.
func NewInstrumentedTicker(inner Ticker, store *MetricsStore) Ticker {
	return &instrumentedTicker{inner: inner, store: store}
}

func (t *instrumentedTicker) Tick() (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult) {
	snap, rates, result := t.inner.Tick()
	if snap != nil {
		t.store.Update(snap, rates, result)
	}
	return snap, rates, result
}

func (t *instrumentedTicker) Base() *Engine {
	return t.inner.Base()
}

func writePrometheus(w io.Writer, snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) {
	write := func(format string, args ...interface{}) {
		_, _ = fmt.Fprintf(w, format, args...)
	}

	write("# TYPE xtop_up gauge\n")
	write("xtop_up 1\n")

	if result != nil {
		write("# TYPE xtop_health gauge\n")
		write("xtop_health %d\n", result.Health)
		write("# TYPE xtop_rca_primary_score gauge\n")
		if result.PrimaryBottleneck != "" {
			write("xtop_rca_primary_score{bottleneck=%q} %d\n", result.PrimaryBottleneck, result.PrimaryScore)
		} else {
			write("xtop_rca_primary_score{bottleneck=\"\"} 0\n")
		}
	}

	psi := snap.Global.PSI
	write("# TYPE xtop_psi_cpu_some gauge\n")
	write("xtop_psi_cpu_some %f\n", psi.CPU.Some.Avg10)
	write("# TYPE xtop_psi_cpu_full gauge\n")
	write("xtop_psi_cpu_full %f\n", psi.CPU.Full.Avg10)
	write("# TYPE xtop_psi_mem_some gauge\n")
	write("xtop_psi_mem_some %f\n", psi.Memory.Some.Avg10)
	write("# TYPE xtop_psi_mem_full gauge\n")
	write("xtop_psi_mem_full %f\n", psi.Memory.Full.Avg10)
	write("# TYPE xtop_psi_io_some gauge\n")
	write("xtop_psi_io_some %f\n", psi.IO.Some.Avg10)
	write("# TYPE xtop_psi_io_full gauge\n")
	write("xtop_psi_io_full %f\n", psi.IO.Full.Avg10)

	if rates != nil {
		write("# TYPE xtop_cpu_busy_pct gauge\n")
		write("xtop_cpu_busy_pct %f\n", rates.CPUBusyPct)
		write("# TYPE xtop_cpu_user_pct gauge\n")
		write("xtop_cpu_user_pct %f\n", rates.CPUUserPct)
		write("# TYPE xtop_cpu_system_pct gauge\n")
		write("xtop_cpu_system_pct %f\n", rates.CPUSystemPct)
		write("# TYPE xtop_cpu_iowait_pct gauge\n")
		write("xtop_cpu_iowait_pct %f\n", rates.CPUIOWaitPct)
		write("# TYPE xtop_cpu_steal_pct gauge\n")
		write("xtop_cpu_steal_pct %f\n", rates.CPUStealPct)
	}

	mem := snap.Global.Memory
	if mem.Total > 0 {
		used := float64(mem.Total-mem.Available) / float64(mem.Total) * 100
		write("# TYPE xtop_mem_used_pct gauge\n")
		write("xtop_mem_used_pct %f\n", used)
		write("# TYPE xtop_mem_total_bytes gauge\n")
		write("xtop_mem_total_bytes %d\n", mem.Total)
		write("# TYPE xtop_mem_available_bytes gauge\n")
		write("xtop_mem_available_bytes %d\n", mem.Available)
	}

	if rates != nil {
		var maxUtil float64
		for _, d := range rates.DiskRates {
			if d.UtilPct > maxUtil {
				maxUtil = d.UtilPct
			}
		}
		write("# TYPE xtop_disk_util_max_pct gauge\n")
		write("xtop_disk_util_max_pct %f\n", maxUtil)

		write("# TYPE xtop_disk_read_mbps gauge\n")
		write("# TYPE xtop_disk_write_mbps gauge\n")
		write("# TYPE xtop_disk_util_pct gauge\n")
		write("# TYPE xtop_disk_await_ms gauge\n")
		for _, d := range rates.DiskRates {
			write("xtop_disk_read_mbps{device=%q} %f\n", d.Name, d.ReadMBs)
			write("xtop_disk_write_mbps{device=%q} %f\n", d.Name, d.WriteMBs)
			write("xtop_disk_util_pct{device=%q} %f\n", d.Name, d.UtilPct)
			write("xtop_disk_await_ms{device=%q} %f\n", d.Name, d.AvgAwaitMs)
		}
		var drops, errors float64
		for _, nr := range rates.NetRates {
			drops += nr.RxDropsPS + nr.TxDropsPS
			errors += nr.RxErrorsPS + nr.TxErrorsPS
		}
		write("# TYPE xtop_net_drops_per_sec gauge\n")
		write("xtop_net_drops_per_sec %f\n", drops)
		write("# TYPE xtop_net_errors_per_sec gauge\n")
		write("xtop_net_errors_per_sec %f\n", errors)
		write("# TYPE xtop_net_retrans_per_sec gauge\n")
		write("xtop_net_retrans_per_sec %f\n", rates.RetransRate)

		write("# TYPE xtop_net_rx_mbps gauge\n")
		write("# TYPE xtop_net_tx_mbps gauge\n")
		write("# TYPE xtop_net_util_pct gauge\n")
		write("# TYPE xtop_net_drops_iface_per_sec gauge\n")
		write("# TYPE xtop_net_errors_iface_per_sec gauge\n")
		for _, nr := range rates.NetRates {
			write("xtop_net_rx_mbps{iface=%q} %f\n", nr.Name, nr.RxMBs)
			write("xtop_net_tx_mbps{iface=%q} %f\n", nr.Name, nr.TxMBs)
			write("xtop_net_util_pct{iface=%q} %f\n", nr.Name, nr.UtilPct)
			write("xtop_net_drops_iface_per_sec{iface=%q} %f\n", nr.Name, nr.RxDropsPS+nr.TxDropsPS)
			write("xtop_net_errors_iface_per_sec{iface=%q} %f\n", nr.Name, nr.RxErrorsPS+nr.TxErrorsPS)
		}

		writeCgroupMetrics(w, rates.CgroupRates)
	}
}

func writeCgroupMetrics(w io.Writer, cgs []model.CgroupRate) {
	if len(cgs) == 0 {
		return
	}
	sorted := make([]model.CgroupRate, len(cgs))
	copy(sorted, cgs)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CPUPct > sorted[j].CPUPct
	})
	if len(sorted) > 50 {
		sorted = sorted[:50]
	}
	_, _ = fmt.Fprintln(w, "# TYPE xtop_cgroup_cpu_pct gauge")
	_, _ = fmt.Fprintln(w, "# TYPE xtop_cgroup_mem_pct gauge")
	_, _ = fmt.Fprintln(w, "# TYPE xtop_cgroup_io_read_mbps gauge")
	_, _ = fmt.Fprintln(w, "# TYPE xtop_cgroup_io_write_mbps gauge")
	_, _ = fmt.Fprintln(w, "# TYPE xtop_cgroup_throttle_pct gauge")
	for _, cg := range sorted {
		_, _ = fmt.Fprintf(w, "xtop_cgroup_cpu_pct{path=%q,name=%q} %f\n", cg.Path, cg.Name, cg.CPUPct)
		_, _ = fmt.Fprintf(w, "xtop_cgroup_mem_pct{path=%q,name=%q} %f\n", cg.Path, cg.Name, cg.MemPct)
		_, _ = fmt.Fprintf(w, "xtop_cgroup_io_read_mbps{path=%q,name=%q} %f\n", cg.Path, cg.Name, cg.IORateMBs)
		_, _ = fmt.Fprintf(w, "xtop_cgroup_io_write_mbps{path=%q,name=%q} %f\n", cg.Path, cg.Name, cg.IOWRateMBs)
		_, _ = fmt.Fprintf(w, "xtop_cgroup_throttle_pct{path=%q,name=%q} %f\n", cg.Path, cg.Name, cg.ThrottlePct)
	}
}
