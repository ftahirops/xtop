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
