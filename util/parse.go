package util

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// ReadFileString reads a file and returns its contents as a string.
func ReadFileString(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ReadFileLines reads a file and returns its lines.
func ReadFileLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// ParseKeyValueFile parses a file with "key value" or "key: value" lines.
func ParseKeyValueFile(path string) (map[string]string, error) {
	lines, err := ReadFileLines(path)
	if err != nil {
		return nil, err
	}
	return ParseKeyValueLines(lines), nil
}

// ParseKeyValueLines parses lines with "key value" or "key: value" format.
func ParseKeyValueLines(lines []string) map[string]string {
	m := make(map[string]string)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Try "key: value" first, then "key value"
		var key, val string
		if idx := strings.Index(line, ":"); idx >= 0 {
			key = strings.TrimSpace(line[:idx])
			val = strings.TrimSpace(line[idx+1:])
		} else {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				key = fields[0]
				val = strings.Join(fields[1:], " ")
			} else if len(fields) == 1 {
				key = fields[0]
			}
		}
		if key != "" {
			m[key] = val
		}
	}
	return m
}

// ParseUint64 parses a string to uint64, returning 0 on error.
func ParseUint64(s string) uint64 {
	s = strings.TrimSpace(s)
	// Strip common suffixes like "kB"
	s = strings.TrimSuffix(s, " kB")
	s = strings.TrimSpace(s)
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

// ParseInt parses a string to int, returning 0 on error.
func ParseInt(s string) int {
	s = strings.TrimSpace(s)
	v, _ := strconv.Atoi(s)
	return v
}

// ParseFloat64 parses a string to float64, returning 0 on error.
func ParseFloat64(s string) float64 {
	s = strings.TrimSpace(s)
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

// FieldsAt returns the field at the given index from a whitespace-split line.
// Returns empty string if index is out of bounds.
func FieldsAt(line string, idx int) string {
	fields := strings.Fields(line)
	if idx < len(fields) {
		return fields[idx]
	}
	return ""
}
