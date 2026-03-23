package engine

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

const (
	BottleneckIO      = "IO Starvation"
	BottleneckMemory  = "Memory Pressure"
	BottleneckCPU     = "CPU Contention"
	BottleneckNetwork = "Network Overload"

	// Minimum evidence groups required to declare a bottleneck
	minEvidenceGroups = 2

	// --- Health scoring ---
	rcaScoreCritical      = 60   // PrimaryScore >= this → critical (if trust gate passes)
	rcaScoreDegraded      = 25   // PrimaryScore >= this → degraded (if trust gate passes)
	rcaScoreFloor         = 20   // scores below this are zeroed out (noise gate)
	rcaHealthOKConfidence = 95   // confidence when health is OK (no bottleneck)
	evidenceStrengthMin   = 0.35 // minimum evidence strength for group counting

	// --- OOM / critical evidence ---
	oomKillStrengthThreshold = 0.35  // OOM kill evidence strength to flag critical
	diskExhaustionETASeconds = 300.0 // ETA < this triggers hasCritEvidence

	// --- IO domain ---
	minIOPSForLatency      = 10.0 // ignore devices with fewer IOPS (USB sticks, idle LUNs)
	ioFsFullFreePct        = 15.0 // free% < this → filesystem full
	ioDstateMinCount       = 10   // D-state count >= this forces score bump
	ioDstateBumpScore      = 60   // forced score when D-state count is high
	fsFullGrowthDampenConf = 0.4  // confidence when FS full but not growing
	fsFullUsedPctNoGrowth  = 95.0 // usedPct below this + no growth → dampen

	// --- Memory domain ---
	memOOMMinScore          = 70    // floor score when OOM detected + trust gate
	memSafeAvailPct         = 25.0  // if avail% > this and PSI low → dampen score
	memSafePSISome          = 0.1   // PSI some threshold for safe-memory gate
	memSafePSIFull          = 0.02  // PSI full threshold for safe-memory gate
	memSafeMaxScore         = 20    // cap score to this when memory looks safe
	memLargeSystemGB        = 32.0  // total RAM > this triggers dynamic thresholds
	memLargeSystemFloorMB   = 500.0 // absolute free-memory floor for large systems
	memPSIAccelMinAvg300    = 0.5   // PSI avg300 must exceed this for acceleration
	memReclaimBaseConf      = 0.7   // base confidence for direct reclaim evidence
	memReclaimNoPSIConf     = 0.35  // dampened confidence when PSI shows no pressure
	memPSISomeMinForReclaim = 0.01  // PSI some threshold to dampen reclaim confidence
	slabLeakMinPct          = 5.0   // slab unreclaimable % of RAM to emit evidence
	dotnetAllocStormMBs     = 100.0 // .NET alloc rate threshold for storm evidence
	dotnetThreadPoolQueueN  = 10    // .NET threadpool queue depth for evidence
	jvmHeapPressurePct      = 80.0  // JVM heap used% to emit pressure evidence
	pveSwapMinMB            = 100   // Proxmox VM swap threshold (MB)
	pveSwapMinPSI           = 5.0   // Proxmox VM PSI some threshold for swap evidence
	pveMemLimitWarnPct      = 80.0  // Proxmox VM memory near-limit warning %
	pvePSIMemMinSome        = 10.0  // Proxmox VM PSI memory some threshold

	// --- CPU domain ---
	cpuSafeBusyPct             = 50.0 // CPU busy% below this + low PSI → dampen score
	cpuSafePSISome             = 0.10 // PSI some threshold for safe-CPU gate
	cpuSafePSIFull             = 0.02 // PSI full threshold for safe-CPU gate
	cpuSafeMaxScore            = 30   // cap score to this when CPU looks safe
	cpuStealBonusThreshold     = 5.0  // steal% > this adds bonus score
	cpuStealBonusScore         = 10   // bonus score for steal
	cpuSoftIRQAvgMinForImbal   = 0.1  // avg softIRQ% must exceed for imbalance check
	cpuIRQImbalanceMinRatio    = 3.0  // softIRQ imbalance ratio to emit evidence
	cpuRunQueueDampenThreshold = 0.1  // rqStrength below this dampens GC evidence
	cpuGCPauseDampenFactor     = 0.5  // confidence multiplier when run queue healthy
	dotnetGCPauseMinPct        = 5.0  // .NET GC pause % to emit evidence
	jvmGCPauseMinPct           = 5.0  // JVM GC pause % to emit evidence
	pveCPUThrottleMinPct       = 1.0  // Proxmox VM throttle % to emit evidence
	pveCPUSomeMinPSI           = 5.0  // Proxmox VM CPU PSI some threshold
	cpuIOWaitMinPct            = 5.0  // iowait% to emit evidence

	// --- Network domain ---
	netRetransLowRate          = 5.0   // retrans rate below this dampens confidence
	netRetransLowConf          = 0.4   // dampened confidence for low retrans rate
	netRetransBaseConf         = 0.8   // base confidence for retransmit evidence
	netDropSplitMinRate        = 0.5   // minimum RX/TX drop rate to split evidence
	netTimeWaitEvidenceMin     = 500   // TIME_WAIT count to emit evidence
	netSynSentEvidenceMin      = 5     // SYN_SENT count to emit evidence
	netEphemeralEvidenceMinPct = 30.0  // ephemeral port % to emit evidence
	netUDPErrMinRate           = 0.5   // UDP error rate to emit evidence
	netTCPResetMinRate         = 1.0   // TCP RST rate to emit evidence
	netTCPAttemptFailMinRate   = 1.0   // TCP attempt fail rate to emit evidence
	netNoSecMaxScore           = 25    // max network score when no security evidence + low drops/retrans
	netDropsSoftIRQBonus       = 10    // bonus score when drops + softIRQ both elevated
	netPortScanMinBuckets      = 10    // port scan unique port groups threshold
	netLateralMinDests         = 200   // unique destinations for lateral movement evidence
	netExfilMinMBHr            = 100.0 // outbound MB/hr threshold for exfiltration evidence
	netBPFDropMinRate          = 1.0   // BPF drop reason minimum rate to report
	netBeaconMinSamples        = 5     // minimum beacon sample count for detection

	// --- Hidden latency detection ---
	hiddenLatCPUMaxBusy         = 50.0   // CPU busy must be below this for detection
	hiddenLatMinCtxRate         = 100.0  // min context switch rate to be interesting
	hiddenLatMinWaitRatio       = 500.0  // ctx switches per %CPU for heavy waiting
	hiddenLatSevereWaitRatio    = 5000.0 // wait ratio for severe lock contention diagnosis
	hiddenLatMinWaitPct         = 15.0   // min estimated wait% to flag
	hiddenLatMinWaitRatioForPct = 2000.0 // wait ratio threshold when wait% < hiddenLatMinWaitPct
	hiddenLatUpgradeWaitPct     = 30.0   // estimated wait% to upgrade health to inconclusive
	hiddenLatUpgradeConfidence  = 40     // confidence when upgrading to inconclusive

	// --- Statistical analysis ---
	statAnomalySigma      = 3.0  // z-score sigma threshold for anomaly detection
	statCorrelationMin    = 0.7  // minimum correlation coefficient to surface
	statCorrelationTop    = 5    // max number of top correlations to return
	statCorrelationStrong = 0.85 // correlation above this is "strong"
	statProcessTrackMax   = 20   // max processes to track for behavior profiling
	statProcessMinCPU     = 0.5  // min CPU% to track a process
	statProcessMinIO      = 0.1  // min IO MB/s to track a process
	statProcessAnomalyMax = 5    // max process anomalies to report

	// --- Evidence string display thresholds ---
	ioEvPSISomeMin        = 0.05    // IO PSI some threshold for evidence string
	ioEvPSIFullMin        = 0.01    // IO PSI full threshold for evidence string
	ioEvAwaitMin          = 20.0    // disk await ms for evidence string
	ioEvUtilMin           = 70.0    // disk util% for evidence string
	ioEvDirtyPctMin       = 5.0     // dirty pages % for evidence string
	memEvPSISomeMin       = 0.05    // MEM PSI some threshold for evidence string
	memEvPSIFullMin       = 0.01    // MEM PSI full threshold for evidence string
	memEvAvailPctMin      = 15.0    // MemAvailable % for evidence string
	memEvSwapRateMin      = 0.1     // swap rate MB/s for evidence string
	memEvMajFaultMin      = 10.0    // major faults/s for evidence string
	memEvSlabPctMin       = 5.0     // slab % for evidence string
	cpuEvBusyMin          = 70.0    // CPU busy% for evidence string
	cpuEvPSISomeMin       = 0.05    // CPU PSI some for evidence string
	cpuEvPSIFullMin       = 0.01    // CPU PSI full for evidence string
	cpuEvRunQueueMin      = 1.5     // run queue ratio for evidence string
	cpuEvCtxSwitchPerCore = 30000.0 // ctx switches per core for evidence string
	cpuEvThrottleMin      = 5.0     // cgroup throttle % for evidence string
	cpuEvStealMin         = 5.0     // steal % for evidence string
	netEvDropsMin         = 1.0     // net drops/s for evidence string
	netEvRetransMin       = 5.0     // retrans/s for evidence string
	netEvConntrackPctMin  = 0.7     // conntrack % (0-1) for evidence string
	netEvSoftIRQMin       = 5.0     // softIRQ % for evidence string
	netEvTimeWaitMin      = 5000    // TIME_WAIT count for evidence string
	netEvCloseWaitMin     = 20      // CLOSE_WAIT count for evidence string
	netEvErrorsMin        = 1.0     // net errors/s for evidence string
	netEvEphemeralMin     = 50.0    // ephemeral port % for evidence string
	netEvSynFloodMin      = 100.0   // SYN flood rate for evidence string
	netEvPortScanMin      = 10      // port scan buckets for evidence string
)

// systemProfile holds characteristics that affect threshold scaling.
type systemProfile struct {
	TotalMemGB float64
	NumCPUs    int
	NumDisks   int
	IsVM       bool
}

func buildSystemProfile(snap *model.Snapshot) systemProfile {
	sp := systemProfile{}
	if snap.Global.Memory.Total > 0 {
		sp.TotalMemGB = float64(snap.Global.Memory.Total) / (1024 * 1024 * 1024)
	}
	sp.NumCPUs = snap.Global.CPU.NumCPUs
	if sp.NumCPUs == 0 {
		sp.NumCPUs = 1
	}
	if snap.SysInfo != nil && snap.SysInfo.Virtualization != "" {
		sp.IsVM = true
	}
	if rates := snap.Global.Disks; len(rates) > 0 {
		sp.NumDisks = len(rates)
	}
	return sp
}

// AnalyzeRCA runs all bottleneck detectors and builds the full analysis result.
func AnalyzeRCA(curr *model.Snapshot, rates *model.RateSnapshot, hist *History) *model.AnalysisResult {
	result := &model.AnalysisResult{}

	sp := buildSystemProfile(curr)
	result.RCA = []model.RCAEntry{
		analyzeIO(curr, rates, sp),
		analyzeMemory(curr, rates, sp),
		analyzeCPU(curr, rates, sp),
		analyzeNetwork(curr, rates, sp),
	}

	// Compute v2 domain confidence for each entry
	for i := range result.RCA {
		result.RCA[i].DomainConf = domainConfidence(result.RCA[i].EvidenceV2)
	}

	sort.Slice(result.RCA, func(i, j int) bool {
		return result.RCA[i].Score > result.RCA[j].Score
	})

	// Resolve application identity for all RCA entries
	if curr.Global.AppIdentities != nil {
		for i := range result.RCA {
			if result.RCA[i].TopPID > 0 {
				if id, ok := curr.Global.AppIdentities[result.RCA[i].TopPID]; ok {
					result.RCA[i].TopAppName = id.DisplayName
				}
			}
		}
	}

	// Resolve multi-domain conflict: when top two domains score within 10 points,
	// use cascading-pattern analysis to break the tie.
	if len(result.RCA) >= 2 {
		top := result.RCA[0]
		second := result.RCA[1]
		if top.Score > 0 && second.Score > 0 && top.Score-second.Score < 10 {
			if resolved := resolveDomainConflict(top, second, curr, rates); resolved != "" {
				// Swap entries if the resolved winner is not currently on top
				if result.RCA[0].Bottleneck != resolved && result.RCA[1].Bottleneck == resolved {
					result.RCA[0], result.RCA[1] = result.RCA[1], result.RCA[0]
				}
			}
		}
	}

	// Primary + secondary
	if len(result.RCA) > 0 && result.RCA[0].Score > 0 {
		primary := result.RCA[0]
		result.PrimaryBottleneck = primary.Bottleneck
		result.PrimaryScore = primary.Score
		result.PrimaryEvidence = primary.Evidence
		result.PrimaryChain = primary.Chain
		result.PrimaryCulprit = primary.TopCgroup
		result.PrimaryPID = primary.TopPID
		result.PrimaryProcess = primary.TopProcess
		result.PrimaryAppName = primary.TopAppName
	}

	// Temporal scoring: sustained pressure gets a bonus over transient spikes.
	if hist != nil && result.PrimaryScore > 0 {
		sustainedTicks := 0
		hLen := hist.Len()
		lookback := 20
		if lookback > hLen {
			lookback = hLen
		}
		for i := hLen - 1; i >= hLen-lookback && i >= 0; i-- {
			r := hist.GetRate(i)
			// Use rate snapshot presence + prior primary score via a simple heuristic:
			// if the previous tick had high CPU busy, IO PSI, or mem PSI, count as sustained.
			if r != nil && r.DeltaSec > 0 {
				snap := hist.Get(i)
				if snap != nil {
					maxPSI := snap.Global.PSI.CPU.Some.Avg10
					if snap.Global.PSI.Memory.Some.Avg10 > maxPSI {
						maxPSI = snap.Global.PSI.Memory.Some.Avg10
					}
					if snap.Global.PSI.IO.Some.Avg10 > maxPSI {
						maxPSI = snap.Global.PSI.IO.Some.Avg10
					}
					if maxPSI >= 5.0 || r.CPUBusyPct >= 80 {
						sustainedTicks++
					}
				}
			}
		}
		// Sustained bonus: +5 per 10 ticks sustained (up to +15)
		sustainedBonus := (sustainedTicks / 10) * 5
		if sustainedBonus > 15 {
			sustainedBonus = 15
		}
		result.PrimaryScore += sustainedBonus
		cap100(&result.PrimaryScore)

		if sustainedTicks > 10 {
			result.Sustained = true
			result.SustainedTicks = sustainedTicks
		}
	}

	// Health level — v2: uses trust gate + domain confidence
	if result.PrimaryScore >= rcaScoreCritical {
		primary := result.RCA[0]
		if v2TrustGate(primary.EvidenceV2) {
			result.Health = model.HealthCritical
			result.Confidence = int(primary.DomainConf * 100)
		} else {
			result.Health = model.HealthInconclusive
			result.Confidence = int(primary.DomainConf * 100)
		}
	} else if result.PrimaryScore >= rcaScoreDegraded {
		primary := result.RCA[0]
		if v2TrustGate(primary.EvidenceV2) {
			result.Health = model.HealthDegraded
			result.Confidence = int(primary.DomainConf * 100)
		} else {
			result.Health = model.HealthInconclusive
			result.Confidence = int(primary.DomainConf * 100)
		}
	} else {
		result.Health = model.HealthOK
		result.Confidence = rcaHealthOKConfidence
	}

	// Alert state machine: apply sustained-threshold filtering
	if hist != nil && hist.alert != nil {
		hasCritEvidence := false
		if len(result.RCA) > 0 {
			for _, e := range result.RCA[0].EvidenceV2 {
				if e.ID == "mem.oom.kills" && e.Strength >= oomKillStrengthThreshold && e.Value > 0 {
					hasCritEvidence = true
					break
				}
			}
			if rates != nil {
				for _, mr := range rates.MountRates {
					if mr.ETASeconds > 0 && mr.ETASeconds < diskExhaustionETASeconds {
						hasCritEvidence = true
						break
					}
				}
			}
		}
		result.Health = hist.alert.Update(result.Health, result.PrimaryScore, hasCritEvidence)
	}

	// Propagate system identity
	result.SysInfo = curr.SysInfo

	// Copy CLOSE_WAIT leakers for actions access
	result.CloseWaitLeakers = curr.Global.CloseWaitLeakers

	// DiskGuard state
	if rates != nil && len(rates.MountRates) > 0 {
		result.DiskGuardMounts = rates.MountRates
		result.DiskGuardWorst = WorstDiskGuardState(rates.MountRates)
	}
	result.DiskGuardMode = "Monitor"

	// Capacity
	result.Capacities = ComputeCapacity(curr, rates)

	// Top owners
	result.CPUOwners, result.MemOwners, result.IOOwners, result.NetOwners = ComputeOwners(curr, rates)

	// Warnings
	result.Warnings = ComputeWarnings(curr, rates)

	// Next risk
	for _, w := range result.Warnings {
		if w.Severity == "warn" || w.Severity == "crit" {
			result.NextRisk = fmt.Sprintf("%s: %s (%s)", w.Signal, w.Detail, w.Value)
			break
		}
	}
	if result.NextRisk == "" && len(result.Warnings) > 0 {
		w := result.Warnings[0]
		result.NextRisk = fmt.Sprintf("%s trend (%s)", w.Signal, w.Value)
	}

	// Causal chain — v2 DAG
	if result.PrimaryScore > 0 && len(result.RCA) > 0 && result.RCA[0].EvidenceGroups >= minEvidenceGroups {
		if dag := buildCausalDAG(result, hist.CausalLearner); dag != nil {
			result.CausalDAG = dag
			result.CausalChain = dag.LinearChain
		}
	}

	// Anomaly tracking
	trackAnomaly(result, hist)

	// Hidden latency detection: metrics look fine but threads are waiting
	detectHiddenLatency(curr, rates, result)

	// Actions
	result.Actions = SuggestActions(result)

	// Narrative engine: build human-readable root cause explanation
	result.Narrative = BuildNarrative(result, curr, rates)

	// Enrich narrative with app-specific context (e.g., "MySQL slow because IO")
	if result.Narrative != nil && curr != nil {
		EnrichNarrativeWithApps(result.Narrative, result, curr.Global.Apps.Instances)
	}

	// Temporal causality: update signal onsets and build chain
	UpdateSignalOnsets(hist, result)
	result.TemporalChain = BuildTemporalChain(result, hist)
	if result.Narrative != nil && result.TemporalChain != nil {
		result.Narrative.Temporal = result.TemporalChain.Summary
	}

	// Cross-signal correlation: detect cause-effect pairs across domains
	result.CrossCorrelations = BuildCrossCorrelation(result, hist)

	// Blame attribution: identify top offenders
	result.Blame = ComputeBlame(result, curr, rates)

	// Statistical intelligence
	runStatisticalAnalysis(result, curr, rates, hist)

	// USE Method checklist
	result.USEChecks = BuildUSEChecklist(curr, rates)

	// Impact quantification
	result.ImpactSummary = QuantifyImpact(result, curr, rates)

	return result
}

// isKernelThread returns true for kernel workers and filesystem daemons
// that do IO on behalf of user processes (not the real culprits).
func isKernelThread(comm string) bool {
	// Kernel threads typically have / in name or known prefixes
	kernelPrefixes := []string{
		"kworker/", "jbd2/", "ksoftirqd/", "kswapd", "khugepaged",
		"kcompactd", "writeback", "flush-", "dm-", "md/", "loop",
		"irq/", "migration/", "rcu_", "watchdog/", "cpuhp/",
		"netns", "kdevtmpfs", "oom_reaper", "kauditd", "kthreadd",
		"scsi_", "nvme-", "blkcg_punt",
	}
	for _, prefix := range kernelPrefixes {
		if strings.HasPrefix(comm, prefix) {
			return true
		}
	}
	// Brackets indicate kernel thread: [kworker/0:1]
	if strings.HasPrefix(comm, "[") && strings.HasSuffix(comm, "]") {
		return true
	}
	return false
}

// cleanCgroupName extracts a human-readable name from a cgroup path.
// "/system.slice/docker-abc123.scope" → "docker-abc123"
// "/user.slice/user-1000.slice" → "user-1000"
func cleanCgroupName(path string) string {
	if path == "" || path == "/" {
		return path
	}
	// Take the last path component
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")
	name := parts[len(parts)-1]
	// Remove common suffixes
	name = strings.TrimSuffix(name, ".scope")
	name = strings.TrimSuffix(name, ".service")
	name = strings.TrimSuffix(name, ".slice")
	if name == "" {
		return path
	}
	return name
}

// detectHiddenLatency identifies when all traditional metrics look fine (CPU low,
// memory OK, IO calm) but processes show signs of hidden waiting — high voluntary
// context switches relative to CPU time, suggesting lock contention, futex waits,
// or scheduler delays. This is the "something is slow but metrics look fine" case.
func detectHiddenLatency(curr *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) {
	if rates == nil {
		return
	}

	// Only trigger when system appears healthy or inconclusive
	if result.Health == model.HealthCritical || result.Health == model.HealthDegraded {
		return
	}

	// System must be idle enough that traditional metrics wouldn't explain slowness
	if rates.CPUBusyPct > hiddenLatCPUMaxBusy {
		return
	}

	// Find processes with high voluntary ctx switches but low CPU usage.
	// High vol_ctxsw + low CPU = thread is sleeping/waiting a lot (locks, IO, futexes).
	type waiter struct {
		comm      string
		pid       int
		volRate   float64
		cpuPct    float64
		waitRatio float64 // vol_ctxsw per % CPU — higher = more waiting
	}

	var waiters []waiter
	var totalVolRate float64

	for _, pr := range rates.ProcessRates {
		if isKernelThread(pr.Comm) {
			continue
		}
		if pr.CtxSwitchRate < hiddenLatMinCtxRate {
			continue // not interesting
		}
		totalVolRate += pr.CtxSwitchRate

		// High context switches with low CPU = suspicious
		cpuPct := pr.CPUPct
		if cpuPct < 0.1 {
			cpuPct = 0.1 // avoid division by zero
		}
		ratio := pr.CtxSwitchRate / cpuPct
		if ratio > hiddenLatMinWaitRatio { // switches per % CPU = heavy waiting
			waiters = append(waiters, waiter{
				comm:      pr.Comm,
				pid:       pr.PID,
				volRate:   pr.CtxSwitchRate,
				cpuPct:    pr.CPUPct,
				waitRatio: ratio,
			})
		}
	}

	if len(waiters) == 0 {
		return
	}

	// Sort by wait ratio descending
	sort.Slice(waiters, func(i, j int) bool {
		return waiters[i].waitRatio > waiters[j].waitRatio
	})

	top := waiters[0]

	// Estimate off-CPU percentage: total vol switches / (vol + nonvol) as a proxy
	// This is a rough estimate — true off-CPU requires eBPF, but high voluntary
	// switches with low CPU is a strong signal.
	nCPU := curr.Global.CPU.NumCPUs
	if nCPU == 0 {
		nCPU = 1
	}
	// Rough estimate: each voluntary context switch means ~some microseconds of waiting.
	// At 10000 switches/s with ~100us avg wait, that's ~1s of waiting per second = ~100/nCPU% off-CPU.
	estimatedWaitPct := totalVolRate / float64(nCPU) / 100 // rough scaling
	if estimatedWaitPct > 100 {
		estimatedWaitPct = 100
	}

	// Only flag if the wait seems significant
	if estimatedWaitPct < hiddenLatMinWaitPct && top.waitRatio < hiddenLatMinWaitRatioForPct {
		return
	}

	result.HiddenLatency = true
	result.HiddenLatencyPct = estimatedWaitPct
	result.HiddenLatencyComm = top.comm

	if top.waitRatio > hiddenLatSevereWaitRatio {
		result.HiddenLatencyDesc = fmt.Sprintf(
			"CPU %.0f%% but %s is context-switching %.0f/s with only %.1f%% CPU — likely lock contention or blocking IO. Run: sudo xtop then press 'p' for eBPF probe.",
			rates.CPUBusyPct, top.comm, top.volRate, top.cpuPct)
	} else {
		result.HiddenLatencyDesc = fmt.Sprintf(
			"CPU %.0f%% but threads are waiting (%.0f voluntary switches/s across %d procs). Top waiter: %s. Run: sudo xtop then press 'p' for eBPF off-CPU analysis.",
			rates.CPUBusyPct, totalVolRate, len(waiters), top.comm)
	}

	// Upgrade health to INCONCLUSIVE if it was OK, to flag this isn't truly healthy
	if result.Health == model.HealthOK && estimatedWaitPct > hiddenLatUpgradeWaitPct {
		result.Health = model.HealthInconclusive
		result.Confidence = hiddenLatUpgradeConfidence
	}
}

func cap100(score *int) {
	if *score > 100 {
		*score = 100
	}
}

// fmtAge formats seconds as a human-readable duration (e.g. "23m", "1h12m", "45s").
func fmtAge(seconds int) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%dm", seconds/60)
	}
	h := seconds / 3600
	m := (seconds % 3600) / 60
	if m == 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}

// runStatisticalAnalysis feeds evidence into statistical trackers and populates results.
func runStatisticalAnalysis(result *model.AnalysisResult, curr *model.Snapshot, rates *model.RateSnapshot, hist *History) {
	if hist == nil {
		return
	}

	// 1. Collect all evidence values from this tick
	evidenceMap := make(map[string]float64)
	for _, rca := range result.RCA {
		for _, ev := range rca.EvidenceV2 {
			evidenceMap[ev.ID] = ev.Value
		}
	}

	// 2. Update baselines + z-scores + forecaster + seasonal
	hour := time.Now().Hour()
	for id, val := range evidenceMap {
		hist.Baselines.Update(id, val)
		hist.ZScores.Push(id, val)
		hist.Forecaster.Update(id, val)
		hist.Seasonal.Update(id, val, hour)
	}

	// 3. Update correlator with all pairs
	hist.Correlator.UpdateFromEvidence(evidenceMap)

	// 4. Detect baseline anomalies (>3 sigma from EWMA)
	for id, val := range evidenceMap {
		if hist.Baselines.IsAnomaly(id, val, statAnomalySigma) {
			mean, std, _ := hist.Baselines.Get(id)
			z := hist.Baselines.ZScore(id, val)
			result.BaselineAnomalies = append(result.BaselineAnomalies, model.BaselineAnomaly{
				EvidenceID: id,
				Value:      val,
				Baseline:   mean,
				StdDev:     std,
				ZScore:     z,
				Sigma:      z,
			})
		}
	}

	// 5. Detect z-score anomalies (>3 sigma from sliding window)
	for id, val := range evidenceMap {
		z := hist.ZScores.ZScore(id, val)
		if z > statAnomalySigma || z < -statAnomalySigma {
			mean, std, _ := hist.ZScores.MeanStd(id)
			result.ZScoreAnomalies = append(result.ZScoreAnomalies, model.ZScoreAnomaly{
				EvidenceID: id,
				Value:      val,
				WindowMean: mean,
				WindowStd:  std,
				ZScore:     z,
			})
		}
	}

	// 6. Surface top correlations
	topCorr := hist.Correlator.TopCorrelations(statCorrelationMin, statCorrelationTop)
	for _, tc := range topCorr {
		strength := "moderate"
		if tc.R > statCorrelationStrong || tc.R < -statCorrelationStrong {
			strength = "strong"
		}
		result.Correlations = append(result.Correlations, model.MetricCorrelation{
			MetricA:     tc.A,
			MetricB:     tc.B,
			Coefficient: tc.R,
			Samples:     tc.N,
			Strength:    strength,
		})
	}

	// 7. Build Golden Signal summary
	result.GoldenSignals = buildGoldenSignals(curr, rates)

	// 8. Process behavior profiling — detect processes deviating from their learned profile
	if rates != nil && len(rates.ProcessRates) > 0 {
		tracked := 0
		for _, pr := range rates.ProcessRates {
			if tracked >= statProcessTrackMax {
				break
			}
			if pr.CPUPct < statProcessMinCPU && pr.ReadMBs+pr.WriteMBs < statProcessMinIO {
				continue
			}
			tracked++
			// Key by Comm (not PID) to avoid unbounded map growth from short-lived processes
			cpuID := "proc." + pr.Comm + ".cpu"
			ioID := "proc." + pr.Comm + ".io"

			hist.Baselines.Update(cpuID, pr.CPUPct)
			hist.Baselines.Update(ioID, pr.ReadMBs+pr.WriteMBs)

			if hist.Baselines.IsAnomaly(cpuID, pr.CPUPct, statAnomalySigma) {
				mean, std, _ := hist.Baselines.Get(cpuID)
				result.ProcessAnomalies = append(result.ProcessAnomalies, model.ProcessAnomaly{
					PID: pr.PID, Comm: pr.Comm, Metric: "cpu_pct",
					Current: pr.CPUPct, Baseline: mean, StdDev: std,
					Sigma: hist.Baselines.ZScore(cpuID, pr.CPUPct),
				})
			}
			if hist.Baselines.IsAnomaly(ioID, pr.ReadMBs+pr.WriteMBs, statAnomalySigma) {
				mean, std, _ := hist.Baselines.Get(ioID)
				result.ProcessAnomalies = append(result.ProcessAnomalies, model.ProcessAnomaly{
					PID: pr.PID, Comm: pr.Comm, Metric: "io_mbs",
					Current: pr.ReadMBs + pr.WriteMBs, Baseline: mean, StdDev: std,
					Sigma: hist.Baselines.ZScore(ioID, pr.ReadMBs+pr.WriteMBs),
				})
			}
		}
		if len(result.ProcessAnomalies) > statProcessAnomalyMax {
			sort.Slice(result.ProcessAnomalies, func(i, j int) bool {
				return result.ProcessAnomalies[i].Sigma > result.ProcessAnomalies[j].Sigma
			})
			result.ProcessAnomalies = result.ProcessAnomalies[:statProcessAnomalyMax]
		}
	}

	// 9. Feed causal learning observations
	// Snapshot signalOnsets under hist.mu, then release before calling Observe
	// to avoid nested locking (hist.mu → CausalLearner.mu).
	hist.mu.RLock()
	onsetsCopy := make(map[string]time.Time, len(hist.signalOnsets))
	for k, v := range hist.signalOnsets {
		onsetsCopy[k] = v
	}
	hist.mu.RUnlock()

	for _, rule := range causalRules {
		_, causeFired := evidenceMap[rule.from]
		_, effectFired := evidenceMap[rule.to]
		if causeFired || effectFired {
			causeOnset, cOK := onsetsCopy[rule.from]
			effectOnset, eOK := onsetsCopy[rule.to]
			causeFirst := false
			if cOK && eOK {
				causeFirst = !causeOnset.After(effectOnset)
			} else if cOK && !eOK {
				causeFirst = true
			}
			hist.CausalLearner.Observe(rule.rule, causeFired, effectFired, causeFirst)
		}
	}

	// 10. Feed co-occurrence learning from all fired evidence this tick
	var firedIDs []string
	for id := range evidenceMap {
		firedIDs = append(firedIDs, id)
	}
	if len(firedIDs) >= 2 {
		hist.CausalLearner.ObserveCoOccurrence(firedIDs)
	}
}

// buildGoldenSignals approximates Google SRE Golden Signals from /proc data.
func buildGoldenSignals(curr *model.Snapshot, rates *model.RateSnapshot) *model.GoldenSignalSummary {
	gs := &model.GoldenSignalSummary{}
	if curr == nil {
		return gs
	}

	// Latency: worst disk await + max PSI stall
	if rates != nil {
		for _, d := range rates.DiskRates {
			if d.AvgAwaitMs > gs.DiskLatencyMs {
				gs.DiskLatencyMs = d.AvgAwaitMs
			}
		}
	}
	psiMax := curr.Global.PSI.CPU.Some.Avg10
	if curr.Global.PSI.Memory.Some.Avg10 > psiMax {
		psiMax = curr.Global.PSI.Memory.Some.Avg10
	}
	if curr.Global.PSI.IO.Full.Avg10 > psiMax {
		psiMax = curr.Global.PSI.IO.Full.Avg10
	}
	gs.PSIStallPct = psiMax

	// Traffic: TCP segments + bytes
	if rates != nil {
		gs.TCPSegmentsPerSec = rates.InSegRate + rates.OutSegRate
		var totalMBs float64
		for _, nr := range rates.NetRates {
			totalMBs += nr.RxMBs + nr.TxMBs
		}
		gs.NetBytesPerSec = totalMBs * 1024 * 1024 // convert MB/s → B/s

		// Error: drops + retrans + resets + OOM
		var totalDrops float64
		for _, nr := range rates.NetRates {
			totalDrops += nr.RxDropsPS + nr.TxDropsPS
		}
		gs.ErrorRate = totalDrops + rates.RetransRate + rates.TCPResetRate + float64(rates.OOMKillDelta)

		// Saturation: max of conntrack%, ephemeral%, runqueue/cores, PSI
		sat := psiMax / 100 // normalize to 0-1
		if curr.Global.Conntrack.Max > 0 {
			ctPct := float64(curr.Global.Conntrack.Count) / float64(curr.Global.Conntrack.Max)
			if ctPct > sat {
				sat = ctPct
			}
		}
		nCPUs := curr.Global.CPU.NumCPUs
		if nCPUs == 0 {
			nCPUs = 1
		}
		rqRatio := curr.Global.CPU.LoadAvg.Load1 / float64(nCPUs)
		if rqRatio > 1 {
			rqRatio = 1
		}
		if rqRatio > sat {
			sat = rqRatio
		}
		gs.SaturationPct = sat * 100
	}

	return gs
}

// resolveDomainConflict uses known cascading patterns to break a tie
// when the top two domain scores are within 10 points of each other.
func resolveDomainConflict(top, second model.RCAEntry, curr *model.Snapshot, rates *model.RateSnapshot) string {
	// Memory reclaim causing IO → prefer Memory as root cause
	if top.Bottleneck == BottleneckIO && second.Bottleneck == BottleneckMemory {
		if rates != nil && rates.DirectReclaimRate > 0 {
			return BottleneckMemory
		}
	}
	// CPU appears dominant but memory PSI exceeds CPU PSI → memory is root cause
	if top.Bottleneck == BottleneckCPU && second.Bottleneck == BottleneckMemory {
		if curr.Global.PSI.Memory.Some.Avg10 > curr.Global.PSI.CPU.Some.Avg10 {
			return BottleneckMemory
		}
	}
	// CPU appears dominant but high iowait → IO is root cause of CPU waiting
	if top.Bottleneck == BottleneckCPU && second.Bottleneck == BottleneckIO {
		if rates != nil && rates.CPUIOWaitPct > rates.CPUBusyPct*0.3 {
			return BottleneckIO
		}
	}
	return "" // no resolution, keep original ranking
}

// evidenceCategory classifies an evidence ID into a weight category for
// the trust gate diversity check. This is independent of the weight tag
// used by scoring — it groups evidence by data-source type.
func evidenceCategory(id string) string {
	switch {
	case strings.Contains(id, "psi"):
		return "psi"
	case strings.Contains(id, "latency"), strings.Contains(id, "await"):
		return "latency"
	case strings.Contains(id, "queue"), strings.Contains(id, "dstate"), strings.Contains(id, "runq"):
		return "queue"
	default:
		return "secondary"
	}
}
