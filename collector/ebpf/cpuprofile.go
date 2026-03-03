package ebpf

import (
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// StackSample represents a single stack trace sample.
type StackSample struct {
	PID          int
	UserStackID  int32
	KernStackID  int32
	Count        uint64
	UserAddrs    []uint64
	KernAddrs    []uint64
}

// FoldedStack represents a collapsed stack trace with count.
type FoldedStack struct {
	Stack string // semicolon-separated function names (callee first)
	Count uint64
}

// ResolveFoldedStacks resolves stack addresses to function names.
func ResolveFoldedStacks(samples []StackSample, pid int) []FoldedStack {
	// Load symbol maps for the target PID
	symMap := loadProcMaps(pid)
	elfSyms := loadELFSymbols(pid, symMap)

	folded := make(map[string]uint64)

	for _, s := range samples {
		var frames []string

		// Kernel frames (bottom of stack)
		for _, addr := range s.KernAddrs {
			if addr == 0 {
				continue
			}
			name := resolveKernelSymbol(addr)
			if name != "" {
				frames = append(frames, name)
			}
		}

		// User frames (top of stack)
		for _, addr := range s.UserAddrs {
			if addr == 0 {
				continue
			}
			name := resolveUserSymbol(addr, elfSyms, symMap)
			if name != "" {
				frames = append(frames, name)
			}
		}

		if len(frames) == 0 {
			frames = []string{"[unknown]"}
		}

		// Reverse for callee-first ordering (standard flamegraph format)
		for i, j := 0, len(frames)-1; i < j; i, j = i+1, j-1 {
			frames[i], frames[j] = frames[j], frames[i]
		}

		key := strings.Join(frames, ";")
		folded[key] += s.Count
	}

	// Convert to sorted slice
	result := make([]FoldedStack, 0, len(folded))
	for stack, count := range folded {
		result = append(result, FoldedStack{Stack: stack, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})
	return result
}

// procMapEntry represents a /proc/PID/maps entry.
type procMapEntry struct {
	StartAddr uint64
	EndAddr   uint64
	Perms     string
	Offset    uint64
	Path      string
}

func loadProcMaps(pid int) []procMapEntry {
	path := fmt.Sprintf("/proc/%d/maps", pid)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var entries []procMapEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Format: start-end perms offset dev inode pathname
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		addrs := strings.SplitN(fields[0], "-", 2)
		if len(addrs) != 2 {
			continue
		}
		startAddr, _ := strconv.ParseUint(addrs[0], 16, 64)
		endAddr, _ := strconv.ParseUint(addrs[1], 16, 64)
		offset, _ := strconv.ParseUint(fields[2], 16, 64)
		path := ""
		if len(fields) >= 6 {
			path = fields[5]
		}
		entries = append(entries, procMapEntry{
			StartAddr: startAddr,
			EndAddr:   endAddr,
			Perms:     fields[1],
			Offset:    offset,
			Path:      path,
		})
	}
	return entries
}

// elfSymbolEntry is a symbol from an ELF file.
type elfSymbolEntry struct {
	Addr uint64
	Name string
	Size uint64
}

func loadELFSymbols(pid int, maps []procMapEntry) []elfSymbolEntry {
	seen := make(map[string]bool)
	var allSyms []elfSymbolEntry

	for _, m := range maps {
		if m.Path == "" || strings.HasPrefix(m.Path, "[") {
			continue
		}
		if seen[m.Path] {
			continue
		}
		seen[m.Path] = true

		// Try to open the ELF file
		path := m.Path
		// For the target process, try /proc/PID/root prefix for containers
		procPath := fmt.Sprintf("/proc/%d/root%s", pid, m.Path)
		if _, err := os.Stat(procPath); err == nil {
			path = procPath
		}

		ef, err := elf.Open(path)
		if err != nil {
			continue
		}

		syms, _ := ef.Symbols()
		for _, s := range syms {
			if s.Value > 0 && s.Name != "" {
				allSyms = append(allSyms, elfSymbolEntry{
					Addr: s.Value,
					Name: s.Name,
					Size: s.Size,
				})
			}
		}

		dynSyms, _ := ef.DynamicSymbols()
		for _, s := range dynSyms {
			if s.Value > 0 && s.Name != "" {
				allSyms = append(allSyms, elfSymbolEntry{
					Addr: s.Value,
					Name: s.Name,
					Size: s.Size,
				})
			}
		}
		ef.Close()
	}

	sort.Slice(allSyms, func(i, j int) bool { return allSyms[i].Addr < allSyms[j].Addr })
	return allSyms
}

func resolveUserSymbol(addr uint64, syms []elfSymbolEntry, maps []procMapEntry) string {
	// Find which map this address belongs to
	for _, m := range maps {
		if addr >= m.StartAddr && addr < m.EndAddr {
			// Adjust address for the ELF file offset
			fileAddr := addr - m.StartAddr + m.Offset
			// Binary search in symbols
			for _, s := range syms {
				if fileAddr >= s.Addr && fileAddr < s.Addr+s.Size {
					return s.Name
				}
			}
			// Try without offset adjustment
			for _, s := range syms {
				if addr >= s.Addr && addr < s.Addr+s.Size {
					return s.Name
				}
			}
			return fmt.Sprintf("[%s+0x%x]", baseName(m.Path), addr-m.StartAddr)
		}
	}
	return fmt.Sprintf("[0x%x]", addr)
}

func resolveKernelSymbol(addr uint64) string {
	// Read /proc/kallsyms (requires root)
	// For performance, cache this; for now just format the address
	return fmt.Sprintf("[k:0x%x]", addr)
}

func baseName(path string) string {
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		return path[idx+1:]
	}
	return path
}
