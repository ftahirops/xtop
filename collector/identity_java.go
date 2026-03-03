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
