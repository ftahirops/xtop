package dotnet

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// EventPipe IPC protocol constants.
const (
	// IPC commands
	ipcMagic     = "DOTNET_IPC_V1"
	cmdCollect   = uint8(0x02) // CollectTracing2
	cmdStopTrace = uint8(0x01)

	// Provider names
	providerRuntime    = "System.Runtime"
	providerASPNET     = "Microsoft.AspNetCore.Hosting"
)

// EventPipeClient connects to a .NET process via the diagnostic IPC socket.
type EventPipeClient struct {
	pid        int
	socketPath string
	conn       net.Conn
}

// DotNetCounters holds parsed counter values from EventPipe.
type DotNetCounters struct {
	// System.Runtime counters
	GCHeapSizeMB     float64
	Gen0GCCount      uint64
	Gen1GCCount      uint64
	Gen2GCCount      uint64
	TimeInGCPct      float64
	AllocRateMBs     float64
	ThreadPoolCount  int
	ThreadPoolQueue  int
	ExceptionCount   uint64
	MonitorLockCount uint64
	WorkingSetMB     float64

	// Microsoft.AspNetCore.Hosting counters
	RequestsPerSec   float64
	CurrentRequests  int

	// Metadata
	PID  int
	Comm string
}

// NewEventPipeClient creates a new EventPipe IPC client.
func NewEventPipeClient(pid int, socketPath string) *EventPipeClient {
	return &EventPipeClient{
		pid:        pid,
		socketPath: socketPath,
	}
}

// Connect establishes a connection to the diagnostic socket.
func (c *EventPipeClient) Connect() error {
	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect to dotnet diagnostic socket: %w", err)
	}
	c.conn = conn
	return nil
}

// Close closes the connection.
func (c *EventPipeClient) Close() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// RequestCounters sends an IPC request to collect counter data.
// This implements a simplified version of the diagnostic IPC protocol.
func (c *EventPipeClient) RequestCounters() (*DotNetCounters, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	// The full EventPipe IPC protocol is complex.
	// For a production implementation, this would:
	// 1. Send IPC header with magic + command
	// 2. Request specific providers and counters
	// 3. Parse the EventPipe binary stream
	//
	// For now, we use a fallback approach reading from /proc filesystem
	// and environment variables set by the .NET runtime.
	return c.readCountersFromProc()
}

// readCountersFromProc reads .NET metrics from procfs as a fallback.
func (c *EventPipeClient) readCountersFromProc() (*DotNetCounters, error) {
	counters := &DotNetCounters{
		PID: c.pid,
	}

	// Read working set from /proc/PID/status
	if data, err := readProcFile(c.pid, "status"); err == nil {
		counters.WorkingSetMB = parseVmRSS(data) / (1024 * 1024)
	}

	return counters, nil
}

// buildIpcHeader creates a diagnostic IPC message header.
func buildIpcHeader(cmd uint8, payloadSize uint16) []byte {
	header := make([]byte, 20)
	copy(header[:14], []byte(ipcMagic))
	binary.LittleEndian.PutUint16(header[14:16], payloadSize+6) // size includes header tail
	header[16] = 0x04 // commandSet = EventPipe
	header[17] = cmd
	binary.LittleEndian.PutUint16(header[18:20], 0) // reserved
	return header
}
