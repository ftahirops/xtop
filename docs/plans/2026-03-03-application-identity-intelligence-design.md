# Application Identity Intelligence Design

## Problem

When xtop says "java(1234) is the culprit", users don't know WHAT java is. Is it Elasticsearch? Kafka? A custom app? The same problem exists for python, node, dotnet, and wrapper processes. We need to resolve raw process comm names to actual application identities.

## Solution

An IdentityCollector that scans ALL processes on the system, resolves each PID to an AppIdentity (application name, version, binary path, systemd unit, container info, parent chain), caches results per PID lifetime, and makes identity available everywhere culprits are displayed.

## Data Model

```go
type AppIdentity struct {
    PID           int
    Comm          string    // raw comm ("java")
    AppName       string    // resolved ("Elasticsearch")
    AppVersion    string    // if detectable ("8.12.0")
    BinaryPath    string    // /proc/PID/exe target
    Cmdline       string    // full cmdline
    ServiceUnit   string    // systemd unit name
    ContainerID   string    // container ID prefix
    ContainerName string    // container name if available
    ParentComm    string    // parent process comm
    ParentPID     int
    UserName      string    // uid to username
    CgroupPath    string
    DisplayName   string    // pre-formatted for UI
}
```

Added to `GlobalMetrics.AppIdentities map[int]AppIdentity`.

## Resolution Chain (Priority Order)

1. Java cmdline: -jar *.jar, -cp *MainClass, known jar names
2. Python cmdline: -m module, script name, known frameworks
3. Node.js cmdline: main script, pm2, npx
4. .NET cmdline: assembly DLL name
5. Systemd unit name (from cgroup)
6. Docker container name (from cgroup)
7. K8s pod (from cgroup)
8. Binary path basename
9. Comm fallback

## Known Application Fingerprints

Java: elasticsearch, kafka, cassandra, zookeeper, logstash, jenkins, tomcat/catalina, spring-boot, wildfly/jboss, hadoop, spark, flink, solr, neo4j, gradle, maven
Python: gunicorn, uvicorn, django, flask, celery, fastapi, airflow, jupyter
Node: pm2, next, nuxt, express (from package.json path)
.NET: assembly name from DLL

## Architecture

- `collector/identity.go` - IdentityCollector with PID cache
- `collector/identity_java.go` - Java fingerprinting
- `collector/identity_rules.go` - Python/Node/.NET/generic rules
- Cache eviction: PID disappears from /proc -> remove
- Runs after ProcessCollector in registry

## Integration Points

- RCAEntry.TopAppName, AnalysisResult.PrimaryAppName
- BlameEntry.AppName
- Narrative engine uses AppName
- UI overview RCA box, blame list, impact scores
- Intel page runtime tables
- Markdown export

## DisplayName Format

- "Elasticsearch [java, elasticsearch.service]"
- "nginx [nginx.service]"
- "docker:abc123 [python]"
- "mysql" (when comm IS the app)
