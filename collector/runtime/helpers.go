package runtime

import "strconv"

func atoi(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

func atoui64(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

func atof(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}
