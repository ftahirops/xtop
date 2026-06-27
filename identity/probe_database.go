package identity

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

const dbProbeTimeout = 3 * time.Second

// probeDatabases checks health and inventory for detected database services.
func probeDatabases(id *model.ServerIdentity) {
	probeMySQL(id)
	probePostgreSQL(id)
	probeRedis(id)
	probeMongoDB(id)
}

func probeMySQL(id *model.ServerIdentity) {
	svc := id.ServiceByName("mysql")
	if svc == nil || !svc.Running {
		return
	}

	// Check health via mysqladmin ping
	if path, err := exec.LookPath("mysqladmin"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), dbProbeTimeout)
		out, err := exec.CommandContext(ctx, path, "ping", "--connect-timeout=2").CombinedOutput()
		cancel()
		if err == nil && strings.Contains(string(out), "alive") {
			svc.Healthy = true
		}
	}

	// List databases
	if path, err := exec.LookPath("mysql"); err == nil {
		ctx1, cancel1 := context.WithTimeout(context.Background(), dbProbeTimeout)
		out, err := exec.CommandContext(ctx1, path, "-N", "-e", "SHOW DATABASES").Output()
		cancel1()
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				db := strings.TrimSpace(line)
				if db == "" || db == "information_schema" || db == "performance_schema" || db == "sys" {
					continue
				}
				info := model.DatabaseInfo{
					Engine: "mysql",
					Name:   db,
				}
				id.Databases = append(id.Databases, info)
			}
		}

		// Check replication — try REPLICA STATUS (8.0.22+) then fall back to SLAVE STATUS
		ctx2, cancel2 := context.WithTimeout(context.Background(), dbProbeTimeout)
		out, err = exec.CommandContext(ctx2, path, "-N", "-e", "SHOW REPLICA STATUS\\G").Output()
		cancel2()
		if err != nil || !strings.Contains(string(out), "Replica_IO_Running") {
			ctx3, cancel3 := context.WithTimeout(context.Background(), dbProbeTimeout)
			out, err = exec.CommandContext(ctx3, path, "-N", "-e", "SHOW SLAVE STATUS\\G").Output()
			cancel3()
		}
		if err == nil {
			status := string(out)
			if strings.Contains(status, "Replica_IO_Running") || strings.Contains(status, "Slave_IO_Running") {
				// Update last database info with replica role
				for i := range id.Databases {
					if id.Databases[i].Engine == "mysql" {
						id.Databases[i].ReplicaRole = "replica"
					}
				}
			}
		}
	}
}

func probePostgreSQL(id *model.ServerIdentity) {
	svc := id.ServiceByName("postgresql")
	if svc == nil || !svc.Running {
		return
	}

	// Check health via pg_isready
	if path, err := exec.LookPath("pg_isready"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), dbProbeTimeout)
		err := exec.CommandContext(ctx, path, "-t", "2").Run()
		cancel()
		if err == nil {
			svc.Healthy = true
		}
	}

	// List databases
	if path, err := exec.LookPath("psql"); err == nil {
		ctx1, cancel1 := context.WithTimeout(context.Background(), dbProbeTimeout)
		out, err := exec.CommandContext(ctx1, path, "-U", "postgres", "-t", "-A", "-c",
			"SELECT datname FROM pg_database WHERE NOT datistemplate").Output()
		cancel1()
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				db := strings.TrimSpace(line)
				if db == "" {
					continue
				}
				info := model.DatabaseInfo{
					Engine: "postgresql",
					Name:   db,
				}
				id.Databases = append(id.Databases, info)
			}
		}

		// Check replication role
		ctx2, cancel2 := context.WithTimeout(context.Background(), dbProbeTimeout)
		out, err = exec.CommandContext(ctx2, path, "-U", "postgres", "-t", "-A", "-c",
			"SELECT pg_is_in_recovery()").Output()
		cancel2()
		if err == nil {
			val := strings.TrimSpace(string(out))
			role := "primary"
			if val == "t" {
				role = "replica"
			}
			for i := range id.Databases {
				if id.Databases[i].Engine == "postgresql" {
					id.Databases[i].ReplicaRole = role
				}
			}
		}
	}
}

func probeRedis(id *model.ServerIdentity) {
	svc := id.ServiceByName("redis")
	if svc == nil || !svc.Running {
		return
	}

	if path, err := exec.LookPath("redis-cli"); err == nil {
		ctx1, cancel1 := context.WithTimeout(context.Background(), dbProbeTimeout)
		out, err := exec.CommandContext(ctx1, path, "ping").Output()
		cancel1()
		if err == nil && strings.TrimSpace(string(out)) == "PONG" {
			svc.Healthy = true
		}

		// Get keyspace info
		ctx2, cancel2 := context.WithTimeout(context.Background(), dbProbeTimeout)
		out, err = exec.CommandContext(ctx2, path, "info", "keyspace").Output()
		cancel2()
		if err == nil {
			info := string(out)
			for _, line := range strings.Split(info, "\n") {
				if strings.HasPrefix(line, "db") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						id.Databases = append(id.Databases, model.DatabaseInfo{
							Engine: "redis",
							Name:   parts[0],
						})
					}
				}
			}
		}
	}
}

func probeMongoDB(id *model.ServerIdentity) {
	svc := id.ServiceByName("mongodb")
	if svc == nil || !svc.Running {
		return
	}

	if path, err := exec.LookPath("mongosh"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), dbProbeTimeout)
		out, err := exec.CommandContext(ctx, path, "--quiet", "--eval", "db.adminCommand('ping')").Output()
		cancel()
		if err == nil && strings.Contains(string(out), "ok") {
			svc.Healthy = true
		}
	}
}
