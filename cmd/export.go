package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ftahirops/xtop/store"
)

// runExport implements the `xtop export` subcommand.
func runExport(args []string) error {
	incidentID := ""
	format := "json"
	outputFile := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--incident":
			if i+1 < len(args) {
				i++
				incidentID = args[i]
			}
		case "--format":
			if i+1 < len(args) {
				i++
				format = args[i]
			}
		case "-o":
			if i+1 < len(args) {
				i++
				outputFile = args[i]
			}
		}
	}

	if incidentID == "" {
		return fmt.Errorf("usage: xtop export --incident <id> [--format json|md] [-o file]")
	}

	dbPath := incidentDBPath()
	st, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("cannot open incident database: %w", err)
	}
	defer st.Close()

	rec, err := st.GetIncident(incidentID)
	if err != nil {
		return fmt.Errorf("incident %q not found: %w", incidentID, err)
	}

	offenders, _ := st.GetOffenders(incidentID)
	fpInfo, _ := st.GetFingerprint(rec.Fingerprint)

	// Redirect output if -o specified
	out := os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	switch format {
	case "md":
		oldStdout := os.Stdout
		os.Stdout = out
		err = incidentMarkdown(rec, offenders, fpInfo)
		os.Stdout = oldStdout
		if outputFile != "" {
			fmt.Fprintf(os.Stderr, "Exported incident %s to %s (markdown)\n", incidentID, outputFile)
		}
		return err

	default: // json
		data := map[string]interface{}{
			"incident":  rec,
			"offenders": offenders,
		}
		if fpInfo != nil {
			data["fingerprint"] = fpInfo
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(data); err != nil {
			return err
		}
		if outputFile != "" {
			fmt.Fprintf(os.Stderr, "Exported incident %s to %s (json)\n", incidentID, outputFile)
		}
		return nil
	}
}
