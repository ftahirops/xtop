package ui

import "os"

func removeFileOS(path string) error {
	return os.Remove(path)
}

func readFileBytesOS(path string) ([]byte, error) {
	return os.ReadFile(path)
}
