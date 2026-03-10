//go:build linux

package apps

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

type kafkaModule struct{}

func NewKafkaModule() AppModule { return &kafkaModule{} }

func (m *kafkaModule) Type() string        { return "kafka" }
func (m *kafkaModule) DisplayName() string { return "Kafka" }

func (m *kafkaModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm != "java" {
			continue
		}
		cmdline := readProcCmdline(p.PID)
		if !strings.Contains(cmdline, "kafka.Kafka") &&
			!strings.Contains(cmdline, "kafka-server-start") &&
			!strings.Contains(cmdline, "kafka.server") {
			continue
		}
		apps = append(apps, DetectedApp{
			PID:     p.PID,
			Port:    9092,
			Comm:    p.Comm,
			Cmdline: cmdline,
			Index:   len(apps),
		})
	}
	return apps
}

func (m *kafkaModule) Collect(app *DetectedApp, _ *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "kafka",
		DisplayName: "Kafka",
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
		DeepMetrics: make(map[string]string),
	}

	// Tier 1: process metrics
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)

	cmdline := app.Cmdline
	if cmdline == "" {
		cmdline = readProcCmdline(app.PID)
	}

	// ---- Tier 2: Deep Metrics ----

	// Parse JMX port from cmdline
	if jmxPort := parseKafkaJMXPort(cmdline); jmxPort != "" {
		inst.DeepMetrics["jmx_port"] = jmxPort
	}

	// Parse Kafka version from classpath in cmdline
	if ver := parseKafkaVersion(cmdline); ver != "" {
		inst.Version = ver
		inst.DeepMetrics["kafka_version"] = ver
	}

	// Parse log dir from cmdline -D flag
	cmdlineLogDir := ""
	if idx := strings.Index(cmdline, "-Dkafka.logs.dir="); idx >= 0 {
		rest := cmdline[idx+len("-Dkafka.logs.dir="):]
		end := strings.IndexAny(rest, " \t")
		if end > 0 {
			cmdlineLogDir = rest[:end]
		} else {
			cmdlineLogDir = rest
		}
	}

	// Config file parsing
	configPaths := []string{
		"/etc/kafka/server.properties",
		"/opt/kafka/config/server.properties",
		"/usr/local/kafka/config/server.properties",
	}
	confPath := findConfigFile(configPaths)
	inst.ConfigPath = confPath

	var confData kafkaConfData
	if confPath != "" {
		confData = parseKafkaServerProperties(confPath)
		inst.HasDeepMetrics = true

		if confData.brokerID != "" {
			inst.DeepMetrics["broker_id"] = confData.brokerID
		}
		if confData.numPartitions != "" {
			inst.DeepMetrics["num_partitions"] = confData.numPartitions
		}
		if confData.logDirs != "" {
			inst.DeepMetrics["log_dirs"] = confData.logDirs
		}
		if confData.logRetentionHours != "" {
			inst.DeepMetrics["log_retention_hours"] = confData.logRetentionHours
		}
		if confData.numIOThreads != "" {
			inst.DeepMetrics["num_io_threads"] = confData.numIOThreads
		}
		if confData.numNetworkThreads != "" {
			inst.DeepMetrics["num_network_threads"] = confData.numNetworkThreads
		}
		if confData.numRecoveryThreads != "" {
			inst.DeepMetrics["num_recovery_threads"] = confData.numRecoveryThreads
		}
		if confData.autoCreateTopics != "" {
			inst.DeepMetrics["auto_create_topics"] = confData.autoCreateTopics
		}
		if confData.defaultReplicationFactor != "" {
			inst.DeepMetrics["default_replication_factor"] = confData.defaultReplicationFactor
		}
	}

	// Use cmdline log dir if config didn't provide one
	logDirs := confData.logDirs
	if logDirs == "" && cmdlineLogDir != "" {
		logDirs = cmdlineLogDir
		inst.DeepMetrics["log_dirs"] = logDirs
	}

	// Log dir disk usage (first dir only, with timeout)
	if logDirs != "" {
		firstDir := strings.Split(logDirs, ",")[0]
		firstDir = strings.TrimSpace(firstDir)
		if sz := kafkaLogDirSizeGB(firstDir); sz != "" {
			inst.DeepMetrics["log_dir_size_gb"] = sz
			inst.HasDeepMetrics = true
		}
	}

	// Try kafka-topics.sh to count topics
	topicCount := kafkaTopicCount(app.Port)
	if topicCount >= 0 {
		inst.DeepMetrics["topic_count"] = fmt.Sprintf("%d", topicCount)
		inst.HasDeepMetrics = true
	}

	// Try kafka-consumer-groups.sh to count consumer groups
	groupCount := kafkaConsumerGroupCount(app.Port)
	if groupCount >= 0 {
		inst.DeepMetrics["consumer_group_count"] = fmt.Sprintf("%d", groupCount)
		inst.HasDeepMetrics = true
	}

	// JVM hsperfdata check
	if hsperfExists(app.PID) {
		inst.DeepMetrics["jvm_hsperfdata"] = "available"
	}

	// ---- Health scoring ----
	inst.HealthScore = 100

	// FD pressure
	if inst.FDs > 100000 {
		inst.HealthScore -= 20
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("very high FD count (%d) — approaching ulimit", inst.FDs))
	} else if inst.FDs > 50000 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("high FD count (%d) — may be approaching ulimit", inst.FDs))
	}

	// Thread count
	if inst.Threads > 500 {
		inst.HealthScore -= 5
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("very high thread count (%d)", inst.Threads))
	}

	// No topics found but CLI was available
	if topicCount == 0 {
		inst.HealthScore -= 5
		inst.HealthIssues = append(inst.HealthIssues,
			"no topics — broker may be misconfigured")
	}

	// Clamp
	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}
	if inst.HealthScore > 100 {
		inst.HealthScore = 100
	}

	return inst
}

// kafkaConfData holds parsed server.properties fields.
type kafkaConfData struct {
	brokerID                 string
	numPartitions            string
	logDirs                  string
	logRetentionHours        string
	numIOThreads             string
	numNetworkThreads        string
	numRecoveryThreads       string
	autoCreateTopics         string
	defaultReplicationFactor string
}

// parseKafkaServerProperties parses Kafka server.properties.
func parseKafkaServerProperties(path string) kafkaConfData {
	f, err := os.Open(path)
	if err != nil {
		return kafkaConfData{}
	}
	defer f.Close()

	var d kafkaConfData
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "broker.id":
			d.brokerID = val
		case "num.partitions":
			d.numPartitions = val
		case "log.dirs", "log.dir":
			d.logDirs = val
		case "log.retention.hours":
			d.logRetentionHours = val
		case "num.io.threads":
			d.numIOThreads = val
		case "num.network.threads":
			d.numNetworkThreads = val
		case "num.recovery.threads.per.data.dir":
			d.numRecoveryThreads = val
		case "auto.create.topics.enable":
			d.autoCreateTopics = val
		case "default.replication.factor":
			d.defaultReplicationFactor = val
		}
	}
	return d
}

// parseKafkaJMXPort extracts JMX port from cmdline.
func parseKafkaJMXPort(cmdline string) string {
	re := regexp.MustCompile(`-Dcom\.sun\.management\.jmxremote\.port=(\d+)`)
	if m := re.FindStringSubmatch(cmdline); len(m) == 2 {
		return m[1]
	}
	return ""
}

// parseKafkaVersion tries to extract Kafka version from classpath jars in cmdline.
// Looks for patterns like kafka_2.13-3.5.1 or kafka-clients-3.5.1.jar
func parseKafkaVersion(cmdline string) string {
	// Try kafka_SCALA-VERSION pattern (e.g., kafka_2.13-3.5.1)
	re := regexp.MustCompile(`kafka_[\d.]+-(\d+\.\d+\.\d+)`)
	if m := re.FindStringSubmatch(cmdline); len(m) == 2 {
		return m[1]
	}
	// Try kafka-clients-VERSION pattern
	re2 := regexp.MustCompile(`kafka-clients-(\d+\.\d+\.\d+)`)
	if m := re2.FindStringSubmatch(cmdline); len(m) == 2 {
		return m[1]
	}
	return ""
}

// kafkaTopicCount tries to count topics using kafka-topics.sh or kafka-topics CLI.
// Returns -1 if CLI is not available.
func kafkaTopicCount(port int) int {
	bootstrap := fmt.Sprintf("localhost:%d", port)
	for _, bin := range []string{"kafka-topics.sh", "kafka-topics"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, bin, "--bootstrap-server", bootstrap, "--list")
		out, err := cmd.Output()
		cancel()
		if err != nil {
			continue
		}
		count := 0
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if strings.TrimSpace(line) != "" {
				count++
			}
		}
		return count
	}
	return -1
}

// kafkaConsumerGroupCount tries to count consumer groups using kafka-consumer-groups.sh.
// Returns -1 if CLI is not available.
func kafkaConsumerGroupCount(port int) int {
	bootstrap := fmt.Sprintf("localhost:%d", port)
	for _, bin := range []string{"kafka-consumer-groups.sh", "kafka-consumer-groups"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, bin, "--bootstrap-server", bootstrap, "--list")
		out, err := cmd.Output()
		cancel()
		if err != nil {
			continue
		}
		count := 0
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if strings.TrimSpace(line) != "" {
				count++
			}
		}
		return count
	}
	return -1
}

// kafkaLogDirSizeGB returns the log dir size in GB using du, or "" on failure.
func kafkaLogDirSizeGB(dir string) string {
	if _, err := os.Stat(dir); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "du", "-sb", dir)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	if len(fields) < 1 {
		return ""
	}
	bytes, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return ""
	}
	gb := bytes / (1024 * 1024 * 1024)
	return fmt.Sprintf("%.2f", gb)
}

// hsperfExists checks if JVM hsperfdata exists for a given PID.
func hsperfExists(pid int) bool {
	entries, err := os.ReadDir("/tmp")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "hsperfdata_") {
			continue
		}
		path := fmt.Sprintf("/tmp/%s/%d", e.Name(), pid)
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}
