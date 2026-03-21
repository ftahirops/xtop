package model

// GPUDevice represents one GPU's metrics.
type GPUDevice struct {
	Index       int
	Name        string  // e.g., "NVIDIA GeForce RTX 3090"
	Driver      string  // driver version
	UtilGPU     float64 // GPU utilization %
	UtilMem     float64 // memory controller utilization %
	MemUsed     uint64  // bytes
	MemTotal    uint64  // bytes
	Temperature int     // celsius
	PowerDraw   float64 // watts
	PowerLimit  float64 // watts
	FanSpeed    int     // percent (-1 if N/A)
	Processes   []GPUProcess
}

// GPUProcess represents a process using the GPU.
type GPUProcess struct {
	PID     int
	Name    string
	MemUsed uint64 // bytes
}

// GPUSnapshot holds all GPU data for one collection cycle.
type GPUSnapshot struct {
	Available bool
	Devices   []GPUDevice
}
