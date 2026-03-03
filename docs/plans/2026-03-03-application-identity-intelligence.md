# Application Identity Intelligence Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace bare process names like "java(1234)" with resolved application identities like "Elasticsearch [java, elasticsearch.service]" everywhere culprits appear.

**Architecture:** A new `IdentityCollector` scans all `/proc/*/cmdline` and `/proc/*/exe`, resolves each PID to an `AppIdentity` using a priority chain of heuristic matchers (Java jars, Python modules, Node scripts, systemd units, containers), caches per PID lifetime, and exposes identities via `snap.Global.AppIdentities`. All UI and RCA code looks up this map to display rich names.

**Tech Stack:** Go, Linux procfs, existing collector framework

---

### Task 1: Add AppIdentity Model Types

**Files:**
- Modify: `model/metrics.go` (after RuntimeMetrics, ~line 717)
- Modify: `model/snapshot.go` (AnalysisResult ~line 238, RCAEntry ~line 379, BlameEntry ~line 499)

**Step 1: Add AppIdentity struct to model/metrics.go**

After the `RuntimeMetrics` struct (before `GlobalMetrics`), add:

```go
// AppIdentity holds the resolved application identity for a process.
type AppIdentity struct {
    PID           int
    Comm          string // raw comm from /proc/PID/stat
    AppName       string // resolved application name ("Elasticsearch")
    AppVersion    string // version if detectable
    BinaryPath    string // /proc/PID/exe target
    Cmdline       string // full cmdline (truncated to 256 chars)
    ServiceUnit   string // systemd unit name
    ContainerID   string // container ID prefix (12 chars)
    ParentComm    string // parent process comm
    ParentPID     int
    CgroupPath    string
    DisplayName   string // pre-formatted: "Elasticsearch [java, elasticsearch.service]"
}
```

**Step 2: Add AppIdentities field to GlobalMetrics**

In `GlobalMetrics` struct, after `Runtimes RuntimeMetrics`:

```go
    Runtimes       RuntimeMetrics
    AppIdentities  map[int]AppIdentity // PID → resolved identity
```

**Step 3: Add AppName fields to RCAEntry, AnalysisResult, BlameEntry**

In `model/snapshot.go`:

`RCAEntry` — add after `TopPID int`:
```go
    TopAppName string // resolved app name from identity (empty = use TopProcess)
```

`AnalysisResult` — add after `PrimaryProcess string`:
```go
    PrimaryAppName string // resolved app name for primary culprit
```

`BlameEntry` — add after `Comm string`:
```go
    AppName string // resolved app name from identity
```

**Step 4: Build and verify**

Run: `go build ./...`
Expected: Clean compile

**Step 5: Commit**

```
feat(model): add AppIdentity type and identity fields to RCA/blame structs
```

---

### Task 2: Create Identity Resolver Core

**Files:**
- Create: `collector/identity.go` (~250 lines)

**Step 1: Write the IdentityCollector**

```go
package collector

import (
    "fmt"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "sync"

    "github.com/ftahirops/xtop/model"
    "github.com/ftahirops/xtop/util"
)

// IdentityCollector resolves process PIDs to application identities.
// It caches identities per PID lifetime (cmdline/exe don't change).
type IdentityCollector struct {
    cache map[int]model.AppIdentity
    mu    sync.Mutex
}

func (c *IdentityCollector) Name() string { return "identity" }

func (c *IdentityCollector) Collect(snap *model.Snapshot) error {
    c.mu.Lock()
    defer c.mu.Unlock()

    if c.cache == nil {
        c.cache = make(map[int]model.AppIdentity)
    }

    // Scan /proc for all PIDs
    entries, err := os.ReadDir("/proc")
    if err != nil {
        return nil // non-fatal
    }

    alive := make(map[int]bool)
    for _, e := range entries {
        if !e.IsDir() {
            continue
        }
        pid, err := strconv.Atoi(e.Name())
        if err != nil || pid <= 0 {
            continue
        }
        alive[pid] = true

        // Skip if already cached
        if _, ok := c.cache[pid]; ok {
            continue
        }

        // Resolve identity for new PID
        id := c.resolveIdentity(pid)
        if id.Comm == "" {
            continue // process likely exited during scan
        }
        c.cache[pid] = id
    }

    // Evict dead PIDs
    for pid := range c.cache {
        if !alive[pid] {
            delete(c.cache, pid)
        }
    }

    // Populate snapshot
    snap.Global.AppIdentities = make(map[int]model.AppIdentity, len(c.cache))
    for pid, id := range c.cache {
        snap.Global.AppIdentities[pid] = id
    }

    return nil
}

func (c *IdentityCollector) resolveIdentity(pid int) model.AppIdentity {
    pidDir := fmt.Sprintf("/proc/%d", pid)
    id := model.AppIdentity{PID: pid}

    // Read comm
    if data, err := os.ReadFile(filepath.Join(pidDir, "comm")); err == nil {
        id.Comm = strings.TrimSpace(string(data))
    } else {
        return id // process gone
    }

    // Read cmdline (null-separated)
    if data, err := os.ReadFile(filepath.Join(pidDir, "cmdline")); err == nil {
        cmd := string(data)
        // Replace nulls with spaces for display, truncate
        cmd = strings.ReplaceAll(cmd, "\x00", " ")
        cmd = strings.TrimSpace(cmd)
        if len(cmd) > 256 {
            cmd = cmd[:256]
        }
        id.Cmdline = cmd
    }

    // Read exe symlink
    if target, err := os.Readlink(filepath.Join(pidDir, "exe")); err == nil {
        id.BinaryPath = strings.TrimSuffix(target, " (deleted)")
    }

    // Read cgroup
    if data, err := util.ReadFileString(filepath.Join(pidDir, "cgroup")); err == nil {
        for _, line := range strings.Split(data, "\n") {
            parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
            if len(parts) == 3 && parts[0] == "0" {
                id.CgroupPath = parts[2]
                break
            }
        }
        if id.CgroupPath == "" {
            for _, line := range strings.Split(data, "\n") {
                parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
                if len(parts) == 3 {
                    id.CgroupPath = parts[2]
                    break
                }
            }
        }
    }

    // Read PPID from stat
    if data, err := util.ReadFileString(filepath.Join(pidDir, "stat")); err == nil {
        closeIdx := strings.LastIndex(data, ")")
        if closeIdx > 0 && closeIdx+2 < len(data) {
            fields := strings.Fields(data[closeIdx+2:])
            if len(fields) > 1 {
                id.ParentPID, _ = strconv.Atoi(fields[1])
            }
        }
    }

    // Read parent comm
    if id.ParentPID > 0 {
        if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", id.ParentPID)); err == nil {
            id.ParentComm = strings.TrimSpace(string(data))
        }
    }

    // Resolve service unit from cgroup
    id.ServiceUnit = resolveServiceUnit(id.CgroupPath)

    // Resolve container ID from cgroup
    id.ContainerID = resolveContainerID(id.CgroupPath)

    // Resolve application name using heuristic chain
    id.AppName, id.AppVersion = resolveAppName(id)

    // Build display name
    id.DisplayName = buildDisplayName(id)

    return id
}

// resolveServiceUnit extracts systemd unit name from cgroup path.
func resolveServiceUnit(cgPath string) string {
    if cgPath == "" {
        return ""
    }
    parts := strings.Split(strings.TrimRight(cgPath, "/"), "/")
    for _, p := range parts {
        if strings.HasSuffix(p, ".service") {
            return p
        }
    }
    return ""
}

// resolveContainerID extracts container ID from cgroup path.
func resolveContainerID(cgPath string) string {
    parts := strings.Split(strings.TrimRight(cgPath, "/"), "/")
    for _, p := range parts {
        if p == "docker" || strings.HasPrefix(p, "docker-") {
            leaf := parts[len(parts)-1]
            leaf = strings.TrimPrefix(leaf, "docker-")
            leaf = strings.TrimSuffix(leaf, ".scope")
            if len(leaf) > 12 {
                return leaf[:12]
            }
            return leaf
        }
        if strings.HasPrefix(p, "kubepods") {
            leaf := parts[len(parts)-1]
            // Strip cri-containerd- or similar prefix
            for _, prefix := range []string{"cri-containerd-", "crio-", "docker-"} {
                leaf = strings.TrimPrefix(leaf, prefix)
            }
            leaf = strings.TrimSuffix(leaf, ".scope")
            if len(leaf) > 12 {
                return leaf[:12]
            }
            return leaf
        }
    }
    return ""
}

// resolveAppName runs the heuristic chain to identify the application.
func resolveAppName(id model.AppIdentity) (name, version string) {
    args := strings.Split(strings.ReplaceAll(id.Cmdline, "\x00", " "), " ")

    // Priority 1: Java applications
    if id.Comm == "java" || strings.HasSuffix(id.BinaryPath, "/java") {
        return resolveJavaApp(args)
    }

    // Priority 2: Python applications
    if id.Comm == "python" || id.Comm == "python3" || id.Comm == "python2" {
        return resolvePythonApp(args)
    }

    // Priority 3: Node.js applications
    if id.Comm == "node" {
        return resolveNodeApp(args)
    }

    // Priority 4: .NET applications
    if id.Comm == "dotnet" {
        return resolveDotNetApp(args)
    }

    // Priority 5: Systemd unit name (strip .service)
    if id.ServiceUnit != "" {
        name = strings.TrimSuffix(id.ServiceUnit, ".service")
        return name, ""
    }

    // Priority 6: Container
    if id.ContainerID != "" {
        return "container:" + id.ContainerID, ""
    }

    // Priority 7: Binary path basename (if different from comm and more descriptive)
    if id.BinaryPath != "" {
        base := filepath.Base(id.BinaryPath)
        if base != id.Comm && base != "" && base != "." {
            return base, ""
        }
    }

    // Priority 8: Comm fallback
    return id.Comm, ""
}

// buildDisplayName creates the pre-formatted display string.
func buildDisplayName(id model.AppIdentity) string {
    name := id.AppName
    if name == "" {
        name = id.Comm
    }

    // Add version if available
    if id.AppVersion != "" {
        name += " " + id.AppVersion
    }

    // Build context parts
    var ctx []string
    if id.AppName != id.Comm && id.Comm != "" {
        ctx = append(ctx, id.Comm)
    }
    if id.ServiceUnit != "" && id.ServiceUnit != id.AppName+".service" {
        ctx = append(ctx, id.ServiceUnit)
    }
    if id.ContainerID != "" {
        ctx = append(ctx, "ctr:"+id.ContainerID)
    }

    if len(ctx) > 0 {
        return name + " [" + strings.Join(ctx, ", ") + "]"
    }
    return name
}
```

**Step 2: Build and verify**

Run: `go build ./...`
Expected: Clean compile

**Step 3: Commit**

```
feat(collector): add IdentityCollector with PID cache and resolution chain
```

---

### Task 3: Create Java Fingerprinting

**Files:**
- Create: `collector/identity_java.go` (~100 lines)

**Step 1: Write Java app resolver**

```go
package collector

import (
    "path/filepath"
    "strings"
)

// knownJavaApps maps jar/classpath substrings to human-readable app names.
var knownJavaApps = map[string]string{
    "elasticsearch":  "Elasticsearch",
    "kafka":          "Kafka",
    "cassandra":      "Cassandra",
    "zookeeper":      "ZooKeeper",
    "logstash":       "Logstash",
    "kibana":         "Kibana",
    "jenkins":        "Jenkins",
    "catalina":       "Tomcat",
    "tomcat":         "Tomcat",
    "spring-boot":    "Spring Boot",
    "spring.boot":    "Spring Boot",
    "wildfly":        "WildFly",
    "jboss":          "JBoss",
    "hadoop":         "Hadoop",
    "spark":          "Spark",
    "flink":          "Flink",
    "solr":           "Solr",
    "neo4j":          "Neo4j",
    "gradle":         "Gradle",
    "maven":          "Maven",
    "intellij":       "IntelliJ",
    "jetty":          "Jetty",
    "netty":          "Netty",
    "activemq":       "ActiveMQ",
    "rabbitmq":       "RabbitMQ",
    "h2":             "H2 Database",
    "minecraft":      "Minecraft",
    "sbt":            "SBT",
    "lein":           "Leiningen",
    "clojure":        "Clojure",
    "scala":          "Scala",
    "groovy":         "Groovy",
    "kotlin":         "Kotlin",
    "jmeter":         "JMeter",
    "sonarqube":      "SonarQube",
    "nexus":          "Nexus",
    "artifactory":    "Artifactory",
    "confluent":      "Confluent",
    "presto":         "Presto",
    "trino":          "Trino",
    "hive":           "Hive",
    "druid":          "Druid",
    "pinot":          "Pinot",
    "opentelemetry":  "OpenTelemetry",
    "grafana":        "Grafana",
    "prometheus":     "Prometheus JMX",
}

// resolveJavaApp identifies a Java application from its command line arguments.
func resolveJavaApp(args []string) (name, version string) {
    var jarName string
    var mainClass string

    for i, arg := range args {
        // -jar foo.jar
        if arg == "-jar" && i+1 < len(args) {
            jarName = filepath.Base(args[i+1])
            break
        }
        // Last arg that looks like a class name (contains dots, no dashes)
        if !strings.HasPrefix(arg, "-") && strings.Contains(arg, ".") && !strings.HasSuffix(arg, ".jar") {
            mainClass = arg
        }
    }

    // Try to extract version from jar name: elasticsearch-8.12.0.jar -> 8.12.0
    if jarName != "" {
        name, version = matchJarName(jarName)
        if name != "" {
            return name, version
        }
    }

    // Try main class
    if mainClass != "" {
        lower := strings.ToLower(mainClass)
        for pattern, appName := range knownJavaApps {
            if strings.Contains(lower, pattern) {
                return appName, ""
            }
        }
        // Use last segment of class name
        parts := strings.Split(mainClass, ".")
        return parts[len(parts)-1], ""
    }

    // Scan all args for known patterns
    for _, arg := range args {
        lower := strings.ToLower(arg)
        for pattern, appName := range knownJavaApps {
            if strings.Contains(lower, pattern) {
                return appName, ""
            }
        }
    }

    return "Java App", ""
}

// matchJarName matches a jar filename against known apps and extracts version.
func matchJarName(jar string) (name, version string) {
    lower := strings.ToLower(jar)
    lower = strings.TrimSuffix(lower, ".jar")

    // Check known apps
    for pattern, appName := range knownJavaApps {
        idx := strings.Index(lower, pattern)
        if idx < 0 {
            continue
        }
        // Try to extract version: after pattern, skip separator, grab digits
        rest := lower[idx+len(pattern):]
        rest = strings.TrimLeft(rest, "-_.")
        if rest != "" {
            // Take version-like prefix (digits and dots)
            ver := extractVersion(rest)
            if ver != "" {
                return appName, ver
            }
        }
        return appName, ""
    }

    // Unknown jar: use jar name as app name
    name = strings.TrimSuffix(jar, ".jar")
    // Try to split name-version
    if idx := findVersionSplit(name); idx > 0 {
        return name[:idx], name[idx+1:]
    }
    return name, ""
}

// extractVersion extracts a version string like "8.12.0" from the start of s.
func extractVersion(s string) string {
    var ver []byte
    for _, c := range []byte(s) {
        if c >= '0' && c <= '9' || c == '.' {
            ver = append(ver, c)
        } else {
            break
        }
    }
    result := strings.Trim(string(ver), ".")
    if result == "" || !strings.ContainsAny(result, "0123456789") {
        return ""
    }
    return result
}

// findVersionSplit finds the index of the separator before a version in "name-1.2.3".
func findVersionSplit(s string) int {
    for i := len(s) - 1; i > 0; i-- {
        if s[i] == '-' || s[i] == '_' {
            if i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
                return i
            }
        }
    }
    return -1
}
```

**Step 2: Build and verify**

Run: `go build ./...`
Expected: Clean compile

**Step 3: Commit**

```
feat(collector): add Java application fingerprinting (50+ known apps)
```

---

### Task 4: Create Python/Node/.NET Resolution Rules

**Files:**
- Create: `collector/identity_rules.go` (~80 lines)

**Step 1: Write remaining runtime resolvers**

```go
package collector

import (
    "path/filepath"
    "strings"
)

// resolvePythonApp identifies a Python application from command line args.
func resolvePythonApp(args []string) (name, version string) {
    for i, arg := range args {
        // python -m module_name
        if arg == "-m" && i+1 < len(args) {
            mod := args[i+1]
            switch {
            case strings.Contains(mod, "gunicorn"):
                return "Gunicorn", ""
            case strings.Contains(mod, "uvicorn"):
                return "Uvicorn", ""
            case strings.Contains(mod, "celery"):
                return "Celery", ""
            case strings.Contains(mod, "django"):
                return "Django", ""
            case strings.Contains(mod, "flask"):
                return "Flask", ""
            case strings.Contains(mod, "fastapi"):
                return "FastAPI", ""
            case strings.Contains(mod, "airflow"):
                return "Airflow", ""
            case strings.Contains(mod, "jupyter"):
                return "Jupyter", ""
            case strings.Contains(mod, "pytest"):
                return "pytest", ""
            case strings.Contains(mod, "pip"):
                return "pip", ""
            case strings.Contains(mod, "http.server"):
                return "Python HTTP", ""
            default:
                return mod, ""
            }
        }
    }

    // Check for known framework binaries in args
    for _, arg := range args {
        if strings.HasPrefix(arg, "-") {
            continue
        }
        base := strings.ToLower(filepath.Base(arg))
        switch {
        case strings.Contains(base, "gunicorn"):
            return "Gunicorn", ""
        case strings.Contains(base, "uvicorn"):
            return "Uvicorn", ""
        case strings.Contains(base, "celery"):
            return "Celery", ""
        case strings.Contains(base, "django") || strings.Contains(base, "manage.py"):
            return "Django", ""
        case strings.Contains(base, "airflow"):
            return "Airflow", ""
        case strings.Contains(base, "jupyter"):
            return "Jupyter", ""
        case strings.Contains(base, "supervisord"):
            return "Supervisor", ""
        case strings.HasSuffix(base, ".py"):
            return strings.TrimSuffix(base, ".py"), ""
        }
    }

    return "Python App", ""
}

// resolveNodeApp identifies a Node.js application from command line args.
func resolveNodeApp(args []string) (name, version string) {
    for _, arg := range args {
        if strings.HasPrefix(arg, "-") {
            continue
        }
        base := strings.ToLower(filepath.Base(arg))
        switch {
        case strings.Contains(base, "pm2"):
            return "PM2", ""
        case strings.Contains(base, "next"):
            return "Next.js", ""
        case strings.Contains(base, "nuxt"):
            return "Nuxt.js", ""
        case strings.Contains(base, "nest"):
            return "NestJS", ""
        case strings.Contains(base, "express"):
            return "Express", ""
        case strings.Contains(base, "webpack"):
            return "Webpack", ""
        case strings.Contains(base, "vite"):
            return "Vite", ""
        case strings.Contains(base, "esbuild"):
            return "esbuild", ""
        case strings.Contains(base, "ts-node"):
            return "ts-node", ""
        case strings.Contains(base, "tsx"):
            return "tsx", ""
        case strings.Contains(base, "npx"):
            return "npx", ""
        case strings.HasSuffix(base, ".js") || strings.HasSuffix(base, ".mjs") || strings.HasSuffix(base, ".ts"):
            return strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(base, ".js"), ".mjs"), ".ts"), ""
        }
    }

    return "Node.js App", ""
}

// resolveDotNetApp identifies a .NET application from command line args.
func resolveDotNetApp(args []string) (name, version string) {
    for _, arg := range args {
        if strings.HasPrefix(arg, "-") {
            continue
        }
        base := filepath.Base(arg)
        if strings.HasSuffix(base, ".dll") {
            name = strings.TrimSuffix(base, ".dll")
            return name, ""
        }
        if strings.HasSuffix(base, ".exe") {
            name = strings.TrimSuffix(base, ".exe")
            return name, ""
        }
    }
    return ".NET App", ""
}
```

**Step 2: Build and verify**

Run: `go build ./...`
Expected: Clean compile

**Step 3: Commit**

```
feat(collector): add Python/Node/.NET application resolution rules
```

---

### Task 5: Register IdentityCollector in Engine

**Files:**
- Modify: `collector/collector.go:39-59` (add to default registry)
- Modify: `engine/rca.go:42-51` (populate AppName from identity)
- Modify: `engine/blame.go:77-84,132-139,186-192,206-211` (populate AppName in BlameEntry)

**Step 1: Register IdentityCollector in collector.go**

In `NewRegistry()`, add `&IdentityCollector{}` AFTER `&ProcessCollector{MaxProcs: 50}`:

```go
            &ProcessCollector{MaxProcs: 50},
            &IdentityCollector{},
```

**Step 2: Populate PrimaryAppName in rca.go**

In `AnalyzeRCA()`, after line 50 (`result.PrimaryProcess = primary.TopProcess`), add:

```go
        // Resolve application identity for primary culprit
        if result.PrimaryPID > 0 {
            if id, ok := curr.Global.AppIdentities[result.PrimaryPID]; ok {
                result.PrimaryAppName = id.DisplayName
            }
        }
```

Also, in each domain analyzer (analyzeCPU, analyzeMemory, analyzeIO), after setting TopProcess/TopPID, resolve TopAppName. Add a helper at the bottom of rca.go:

```go
// resolveTopAppName looks up the display name for the top process from identity cache.
func resolveTopAppName(snap *model.Snapshot, pid int) string {
    if snap == nil || snap.Global.AppIdentities == nil || pid <= 0 {
        return ""
    }
    if id, ok := snap.Global.AppIdentities[pid]; ok {
        return id.DisplayName
    }
    return ""
}
```

Then in each domain (after setting TopProcess/TopPID):
- analyzeMemory: after `r.TopProcess = victim.VictimComm` / `r.TopProcess = p.Comm` lines
- analyzeCPU: after the culprit section
- analyzeIO: after `findIOCulprit()` sets `r.TopProcess`

Add: `r.TopAppName = resolveTopAppName(curr, r.TopPID)`

**Step 3: Populate AppName in BlameEntry**

In `engine/blame.go`, in each of the 4 blame functions (blameCPU, blameMemory, blameIO, blameNetwork), add a `snap *model.Snapshot` parameter to the function signature. Then when building each BlameEntry, add after `Comm: p.comm,`:

```go
            AppName: resolveBlameAppName(snap, p.pid),
```

Add helper:
```go
func resolveBlameAppName(snap *model.Snapshot, pid int) string {
    if snap == nil || snap.Global.AppIdentities == nil {
        return ""
    }
    if id, ok := snap.Global.AppIdentities[pid]; ok {
        return id.DisplayName
    }
    return ""
}
```

Update `ComputeBlame()` signature and calls to pass `snap`:
```go
func ComputeBlame(result *model.AnalysisResult, curr *model.Snapshot, rates *model.RateSnapshot) []model.BlameEntry {
```
(Already has `curr` parameter.) Then pass `curr` to each blame function.

**Step 4: Build and verify**

Run: `go build ./...`
Expected: Clean compile (may need to fix caller of ComputeBlame if signature changed — check all callsites)

**Step 5: Commit**

```
feat(engine): integrate identity resolution into RCA culprits and blame
```

---

### Task 6: Update UI to Display Application Names

**Files:**
- Modify: `ui/overview.go:914-921` (RCA box culprit)
- Modify: `ui/overview.go:1265-1268` (explain panel culprit)
- Modify: `ui/overview.go:1556-1561` (blame list)
- Modify: `ui/overview.go:1590-1592` (per-domain culprit)
- Modify: `ui/app.go:1289-1291` (markdown export)

**Step 1: Update RCA box culprit display (overview.go:914-921)**

Replace:
```go
            if result.PrimaryProcess != "" {
                culprit = result.PrimaryProcess
                if result.PrimaryPID > 0 {
                    culprit = fmt.Sprintf("%s(%d)", result.PrimaryProcess, result.PrimaryPID)
                }
            } else if result.PrimaryCulprit != "" && result.PrimaryCulprit != "/" {
                culprit = result.PrimaryCulprit
            }
```

With:
```go
            if result.PrimaryAppName != "" {
                culprit = result.PrimaryAppName
                if result.PrimaryPID > 0 {
                    culprit = fmt.Sprintf("%s (PID %d)", result.PrimaryAppName, result.PrimaryPID)
                }
            } else if result.PrimaryProcess != "" {
                culprit = result.PrimaryProcess
                if result.PrimaryPID > 0 {
                    culprit = fmt.Sprintf("%s(%d)", result.PrimaryProcess, result.PrimaryPID)
                }
            } else if result.PrimaryCulprit != "" && result.PrimaryCulprit != "/" {
                culprit = result.PrimaryCulprit
            }
```

**Step 2: Update explain panel culprit (overview.go:1265-1268)**

Replace:
```go
        if result.PrimaryProcess != "" {
            culprit = truncate(result.PrimaryProcess, 24)
        } else if result.PrimaryCulprit != "" && result.PrimaryCulprit != "/" {
            culprit = truncate(result.PrimaryCulprit, 24)
        }
```

With:
```go
        if result.PrimaryAppName != "" {
            culprit = truncate(result.PrimaryAppName, 30)
        } else if result.PrimaryProcess != "" {
            culprit = truncate(result.PrimaryProcess, 24)
        } else if result.PrimaryCulprit != "" && result.PrimaryCulprit != "/" {
            culprit = truncate(result.PrimaryCulprit, 24)
        }
```

**Step 3: Update blame list (overview.go:1556-1561)**

Replace:
```go
            line := fmt.Sprintf(" %d. %s(%d) — %s",
                i+1,
                truncate(b.Comm, 16),
                b.PID,
                strings.Join(metricParts, ", "))
```

With:
```go
            displayName := b.Comm
            if b.AppName != "" {
                displayName = b.AppName
            }
            line := fmt.Sprintf(" %d. %s (PID %d) — %s",
                i+1,
                truncate(displayName, 22),
                b.PID,
                strings.Join(metricParts, ", "))
```

**Step 4: Update per-domain culprit (overview.go:1590-1592)**

Replace:
```go
        if rca.TopProcess != "" {
            culprit := fmt.Sprintf(" Culprit: %s (PID %d)", valueStyle.Render(rca.TopProcess), rca.TopPID)
            sb.WriteString(boxRow(culprit, innerW) + "\n")
        }
```

With:
```go
        if rca.TopProcess != "" {
            displayName := rca.TopProcess
            if rca.TopAppName != "" {
                displayName = rca.TopAppName
            }
            culprit := fmt.Sprintf(" Culprit: %s (PID %d)", valueStyle.Render(displayName), rca.TopPID)
            sb.WriteString(boxRow(culprit, innerW) + "\n")
        }
```

**Step 5: Update markdown export (app.go:1289-1291)**

Replace:
```go
            if result.PrimaryProcess != "" {
                sb.WriteString(fmt.Sprintf("- **Culprit Process**: %s (PID %d)\n", result.PrimaryProcess, result.PrimaryPID))
            }
```

With:
```go
            if result.PrimaryAppName != "" {
                sb.WriteString(fmt.Sprintf("- **Culprit Application**: %s (PID %d)\n", result.PrimaryAppName, result.PrimaryPID))
            } else if result.PrimaryProcess != "" {
                sb.WriteString(fmt.Sprintf("- **Culprit Process**: %s (PID %d)\n", result.PrimaryProcess, result.PrimaryPID))
            }
```

**Step 6: Build and verify**

Run: `go build ./...`
Expected: Clean compile

**Step 7: Commit**

```
feat(ui): display resolved application names in all culprit locations
```

---

### Task 7: Version Bump, Build, Deploy

**Files:**
- Modify: `cmd/root.go:22`
- Create: `packaging/xtop_0.20.0-1_amd64/DEBIAN/control`
- Modify: `README.md` (all version references)

**Step 1: Bump version to 0.20.0**

In `cmd/root.go`: `var Version = "0.20.0"`

**Step 2: Create packaging control**

Copy from 0.19.0 control, update Version to 0.20.0-1, add "Application identity intelligence" to features list.

**Step 3: Update README**

Replace all `0.19.0` with `0.20.0`.

**Step 4: Build**

```bash
CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/ftahirops/xtop/cmd.Version=0.20.0" -o xtop .
```

**Step 5: go vet**

```bash
go vet ./...
```

**Step 6: Deploy**

```bash
scp -P 2222 xtop root@localhost:/usr/local/bin/xtop
```

**Step 7: Verify**

```bash
ssh -p 2222 root@localhost "xtop --version"
```
Expected: `xtop v0.20.0`

**Step 8: Commit**

```
release: v0.20.0 — application identity intelligence
```
