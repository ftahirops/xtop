package apps

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// ────────────────────────────────────────────────────────────────────────────
// parseContainerInspect tests
// ────────────────────────────────────────────────────────────────────────────

func TestParseContainerInspect_fullPayload(t *testing.T) {
	insp := map[string]interface{}{
		"Created":      "2024-01-15T10:30:00Z",
		"RestartCount": float64(2),
		"Config": map[string]interface{}{
			"User": "appuser",
			"Healthcheck": map[string]interface{}{
				"Test": []interface{}{"CMD", "curl", "-f", "http://localhost/health"},
			},
			"Labels": map[string]interface{}{
				"com.docker.compose.project.working_dir":   "/opt/myapp",
				"com.docker.compose.project.config_files":  "/opt/myapp/docker-compose.yml",
			},
		},
		"HostConfig": map[string]interface{}{
			"RestartPolicy": map[string]interface{}{
				"Name": "unless-stopped",
			},
			"Privileged": false,
			"Memory":     float64(536870912), // 512 MB
			"CpuQuota":   float64(100000),
			"CpuPeriod":  float64(100000),
		},
		"Mounts": []interface{}{
			map[string]interface{}{
				"Type":        "bind",
				"Source":      "/host/data",
				"Destination": "/app/data",
				"RW":          true,
			},
			map[string]interface{}{
				"Type":        "volume",
				"Source":      "myvolume",
				"Destination": "/app/logs",
				"RW":          false,
			},
		},
		"NetworkSettings": map[string]interface{}{
			"Networks": map[string]interface{}{
				"bridge": map[string]interface{}{
					"IPAddress": "172.17.0.2",
					"Gateway":   "172.17.0.1",
				},
			},
			"Ports": map[string]interface{}{
				"8080/tcp": []interface{}{
					map[string]interface{}{
						"HostIp":   "0.0.0.0",
						"HostPort": "32768",
					},
				},
			},
		},
	}

	dc := &model.AppDockerContainer{StackType: "compose"}
	parseContainerInspect(dc, insp)

	if dc.CreatedAt != "2024-01-15T10:30:00Z" {
		t.Errorf("CreatedAt = %q, want 2024-01-15T10:30:00Z", dc.CreatedAt)
	}
	if dc.RestartCount != 2 {
		t.Errorf("RestartCount = %d, want 2", dc.RestartCount)
	}
	if dc.User != "appuser" {
		t.Errorf("User = %q, want appuser", dc.User)
	}
	if !dc.HasHealthChk {
		t.Error("HasHealthChk = false, want true")
	}
	if dc.RestartPolicy != "unless-stopped" {
		t.Errorf("RestartPolicy = %q, want unless-stopped", dc.RestartPolicy)
	}
	if dc.Privileged {
		t.Error("Privileged = true, want false")
	}
	if dc.MemLimit != 536870912 {
		t.Errorf("MemLimit = %d, want 536870912", dc.MemLimit)
	}
	if dc.CPUQuota != 1.0 {
		t.Errorf("CPUQuota = %f, want 1.0", dc.CPUQuota)
	}
	if len(dc.Mounts) != 2 {
		t.Errorf("len(Mounts) = %d, want 2", len(dc.Mounts))
	}
	if dc.Mounts[0].Type != "bind" {
		t.Errorf("Mounts[0].Type = %q, want bind", dc.Mounts[0].Type)
	}
	if dc.Mounts[0].ReadOnly {
		t.Error("Mounts[0].ReadOnly = true, want false (RW=true)")
	}
	if dc.Mounts[1].ReadOnly != true {
		t.Error("Mounts[1].ReadOnly = false, want true (RW=false)")
	}
	if len(dc.Networks) != 1 {
		t.Errorf("len(Networks) = %d, want 1", len(dc.Networks))
	}
	if dc.Networks[0].IP != "172.17.0.2" {
		t.Errorf("Networks[0].IP = %q, want 172.17.0.2", dc.Networks[0].IP)
	}
	if len(dc.Ports) != 1 {
		t.Errorf("len(Ports) = %d, want 1", len(dc.Ports))
	}
	if dc.Ports[0].ContainerPort != 8080 {
		t.Errorf("Ports[0].ContainerPort = %d, want 8080", dc.Ports[0].ContainerPort)
	}
	if dc.Ports[0].HostPort != 32768 {
		t.Errorf("Ports[0].HostPort = %d, want 32768", dc.Ports[0].HostPort)
	}
	if dc.Ports[0].Protocol != "tcp" {
		t.Errorf("Ports[0].Protocol = %q, want tcp", dc.Ports[0].Protocol)
	}
}

func TestParseContainerInspect_nanoCPUs(t *testing.T) {
	insp := map[string]interface{}{
		"HostConfig": map[string]interface{}{
			"NanoCpus":  float64(2e9), // 2 cores via NanoCpus
			"CpuQuota":  float64(0),
			"CpuPeriod": float64(0),
		},
	}
	dc := &model.AppDockerContainer{}
	parseContainerInspect(dc, insp)
	if dc.CPUQuota != 2.0 {
		t.Errorf("CPUQuota from NanoCpus = %f, want 2.0", dc.CPUQuota)
	}
}

func TestParseContainerInspect_malformed(t *testing.T) {
	cases := []struct {
		name string
		insp map[string]interface{}
	}{
		{"nil map", nil},
		{"empty map", map[string]interface{}{}},
		{"wrong type Config", map[string]interface{}{"Config": "notamap"}},
		{"wrong type Mounts", map[string]interface{}{"Mounts": "notaslice"}},
		{"wrong type NetworkSettings", map[string]interface{}{"NetworkSettings": 42}},
		{"wrong type RestartPolicy", map[string]interface{}{
			"HostConfig": map[string]interface{}{
				"RestartPolicy": "should-be-map",
			},
		}},
		{"ports with nil bindings", map[string]interface{}{
			"NetworkSettings": map[string]interface{}{
				"Ports": map[string]interface{}{
					"80/tcp": nil,
				},
			},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dc := &model.AppDockerContainer{}
			// Must not panic
			parseContainerInspect(dc, c.insp)
		})
	}
}

// ────────────────────────────────────────────────────────────────────────────
// applyContainerStats tests
// ────────────────────────────────────────────────────────────────────────────

func makeStatsPayload(totalUsage, preTotalUsage, sysUsage, preSysUsage, onlineCPUs float64,
	memUsage, memLimit float64,
	rxBytes, txBytes float64,
	blkRead, blkWrite float64,
	pids float64,
) map[string]interface{} {
	return map[string]interface{}{
		"cpu_stats": map[string]interface{}{
			"cpu_usage": map[string]interface{}{
				"total_usage": totalUsage,
			},
			"system_cpu_usage": sysUsage,
			"online_cpus":      onlineCPUs,
		},
		"precpu_stats": map[string]interface{}{
			"cpu_usage": map[string]interface{}{
				"total_usage": preTotalUsage,
			},
			"system_cpu_usage": preSysUsage,
		},
		"memory_stats": map[string]interface{}{
			"usage": memUsage,
			"limit": memLimit,
		},
		"networks": map[string]interface{}{
			"eth0": map[string]interface{}{
				"rx_bytes": rxBytes,
				"tx_bytes": txBytes,
			},
		},
		"blkio_stats": map[string]interface{}{
			"io_service_bytes_recursive": []interface{}{
				map[string]interface{}{"op": "Read", "value": blkRead},
				map[string]interface{}{"op": "Write", "value": blkWrite},
			},
		},
		"pids_stats": map[string]interface{}{
			"current": pids,
		},
	}
}

func TestApplyContainerStats_normal(t *testing.T) {
	stats := makeStatsPayload(
		200_000_000, 100_000_000, // cpu: delta = 100M
		1_000_000_000, 500_000_000, // sys: delta = 500M
		4, // 4 online CPUs  → CPU% = (100/500)*4*100 = 80%
		314572800, 1073741824, // mem: ~300MB used of 1GB  → ~30%
		1024, 512, // net rx/tx
		4096, 8192, // blk read/write
		5, // pids
	)

	dc := &model.AppDockerContainer{}
	applyContainerStats(dc, stats)

	if dc.CPUPct < 79.9 || dc.CPUPct > 80.1 {
		t.Errorf("CPUPct = %f, want ~80.0", dc.CPUPct)
	}
	if dc.MemUsedBytes != 314572800 {
		t.Errorf("MemUsedBytes = %f, want 314572800", dc.MemUsedBytes)
	}
	if dc.MemLimitBytes != 1073741824 {
		t.Errorf("MemLimitBytes = %f, want 1073741824", dc.MemLimitBytes)
	}
	if dc.MemPct < 29.0 || dc.MemPct > 30.0 {
		t.Errorf("MemPct = %f, want ~29.3", dc.MemPct)
	}
	if dc.NetRxBytes != 1024 {
		t.Errorf("NetRxBytes = %f, want 1024", dc.NetRxBytes)
	}
	if dc.NetTxBytes != 512 {
		t.Errorf("NetTxBytes = %f, want 512", dc.NetTxBytes)
	}
	if dc.BlockRead != 4096 {
		t.Errorf("BlockRead = %f, want 4096", dc.BlockRead)
	}
	if dc.BlockWrite != 8192 {
		t.Errorf("BlockWrite = %f, want 8192", dc.BlockWrite)
	}
	if dc.PIDs != 5 {
		t.Errorf("PIDs = %d, want 5", dc.PIDs)
	}
}

func TestApplyContainerStats_malformed(t *testing.T) {
	cases := []struct {
		name  string
		stats map[string]interface{}
	}{
		{"nil map", nil},
		{"empty map", map[string]interface{}{}},
		{"cpu_stats wrong type", map[string]interface{}{"cpu_stats": "notamap"}},
		{"memory_stats wrong type", map[string]interface{}{"memory_stats": 42}},
		{"networks wrong type", map[string]interface{}{"networks": "notamap"}},
		{"blkio non-slice", map[string]interface{}{
			"blkio_stats": map[string]interface{}{
				"io_service_bytes_recursive": "notaslice",
			},
		}},
		{"zero sys delta", makeStatsPayload(100, 50, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0)},
		{"negative cpu delta", makeStatsPayload(50, 100, 500, 100, 2, 0, 0, 0, 0, 0, 0, 0)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dc := &model.AppDockerContainer{}
			// Must not panic
			applyContainerStats(dc, c.stats)
		})
	}
}

// ────────────────────────────────────────────────────────────────────────────
// dockerCalcCPU tests
// ────────────────────────────────────────────────────────────────────────────

func TestDockerCalcCPU(t *testing.T) {
	cases := []struct {
		name                string
		stats               map[string]interface{}
		wantLow, wantHigh   float64
	}{
		{
			name: "50pct on 2 cpus",
			stats: map[string]interface{}{
				"cpu_stats": map[string]interface{}{
					"cpu_usage":        map[string]interface{}{"total_usage": float64(100_000_000)},
					"system_cpu_usage": float64(400_000_000),
					"online_cpus":      float64(2),
				},
				"precpu_stats": map[string]interface{}{
					"cpu_usage":        map[string]interface{}{"total_usage": float64(0)},
					"system_cpu_usage": float64(200_000_000),
				},
			},
			wantLow: 99.9, wantHigh: 100.1, // (100M/200M)*2*100 = 100%
		},
		{
			name:    "empty stats → 0",
			stats:   map[string]interface{}{},
			wantLow: 0, wantHigh: 0,
		},
		{
			name: "zero sys delta → 0",
			stats: map[string]interface{}{
				"cpu_stats":    map[string]interface{}{"cpu_usage": map[string]interface{}{"total_usage": float64(100)}, "system_cpu_usage": float64(0)},
				"precpu_stats": map[string]interface{}{"cpu_usage": map[string]interface{}{"total_usage": float64(0)}, "system_cpu_usage": float64(0)},
			},
			wantLow: 0, wantHigh: 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := dockerCalcCPU(c.stats)
			if got < c.wantLow || got > c.wantHigh {
				t.Errorf("dockerCalcCPU = %f, want [%f, %f]", got, c.wantLow, c.wantHigh)
			}
		})
	}
}

// ────────────────────────────────────────────────────────────────────────────
// dockerFmtBytes tests
// ────────────────────────────────────────────────────────────────────────────

func TestDockerFmtBytes(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},           // below 1 KB threshold → raw bytes
		{2048, "2.0 KB"},         // >= 1e3
		{1_500_000, "1.5 MB"},
		{2_500_000_000, "2.5 GB"},
		{3_000_000_000_000, "3.0 TB"},
	}
	for _, c := range cases {
		got := dockerFmtBytes(c.in)
		if got != c.want {
			t.Errorf("dockerFmtBytes(%g) = %q, want %q", c.in, got, c.want)
		}
	}
}
