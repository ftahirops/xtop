package identity

import (
	"os/exec"
	"strings"

	"github.com/ftahirops/xtop/model"
)

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
		out, err := exec.Command(path, "ping", "--connect-timeout=2").CombinedOutput()
		if err == nil && strings.Contains(string(out), "alive") {
			svc.Healthy = true
		}
	}

	// List databases
	if path, err := exec.LookPath("mysql"); err == nil {
		out, err := exec.Command(path, "-N", "-e", "SHOW DATABASES").Output()
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

		// Check replication
		out, err = exec.Command(path, "-N", "-e", "SHOW SLAVE STATUS\\G").Output()
		if err == nil {
			status := string(out)
			if strings.Contains(status, "Slave_IO_Running") {
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
		err := exec.Command(path, "-t", "2").Run()
		if err == nil {
			svc.Healthy = true
		}
	}

	// List databases
	if path, err := exec.LookPath("psql"); err == nil {
		out, err := exec.Command(path, "-U", "postgres", "-t", "-A", "-c",
			"SELECT datname FROM pg_database WHERE NOT datistemplate").Output()
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
		out, err = exec.Command(path, "-U", "postgres", "-t", "-A", "-c",
			"SELECT pg_is_in_recovery()").Output()
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
		out, err := exec.Command(path, "ping").Output()
		if err == nil && strings.TrimSpace(string(out)) == "PONG" {
			svc.Healthy = true
		}

		// Get keyspace info
		out, err = exec.Command(path, "info", "keyspace").Output()
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
		out, err := exec.Command(path, "--quiet", "--eval", "db.adminCommand('ping')").Output()
		if err == nil && strings.Contains(string(out), "ok") {
			svc.Healthy = true
		}
	}
}
