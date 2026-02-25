//go:build 386 || amd64

package ebpf

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/link"
)

type modloadProbe struct {
	objs  modloadObjects
	links []link.Link
}

// ModLoadResult holds a kernel module load event.
type ModLoadResult struct {
	Name  string
	Count uint64
	Ts    uint64
}

func attachModLoad() (*modloadProbe, error) {
	var objs modloadObjects
	if err := loadModloadObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load modload: %w", err)
	}

	l, err := link.Kprobe("do_init_module", objs.HandleDoInitModule, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach do_init_module: %w", err)
	}

	return &modloadProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *modloadProbe) read() ([]ModLoadResult, error) {
	var results []ModLoadResult
	var key uint64
	var val modloadModVal

	iter := p.objs.ModAccum.Iterate()
	for iter.Next(&key, &val) {
		if val.Count == 0 {
			continue
		}
		// Convert [56]int8 to string
		var buf [56]byte
		for i, c := range val.Name {
			buf[i] = byte(c)
		}
		name := strings.TrimRight(string(buf[:]), "\x00")
		results = append(results, ModLoadResult{
			Name:  name,
			Count: val.Count,
			Ts:    val.Ts,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate mod_accum map: %w", err)
	}
	return results, nil
}

// readAndClear reads module load events and deletes them from the map.
func (p *modloadProbe) readAndClear() ([]ModLoadResult, error) {
	var keys []uint64
	var key uint64
	var val modloadModVal

	iter := p.objs.ModAccum.Iterate()
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	results, err := p.read()
	// Delete entries after reading (event-like semantics)
	for _, k := range keys {
		k2 := k
		_ = p.objs.ModAccum.Delete(&k2)
	}
	return results, err
}

func (p *modloadProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
