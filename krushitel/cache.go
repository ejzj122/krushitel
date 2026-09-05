package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
)

const stateTag = 0x1279 ^ 0x1

func statePath() (string, bool) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", false
	}
	return filepath.Join(dir, ".krcache", "s0"), true
}

func readState() bool {
	path, ok := statePath()
	if !ok {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) != 4 {
		return false
	}
	return binary.LittleEndian.Uint32(data) == stateTag
}

func writeState() {
	path, ok := statePath()
	if !ok {
		return
	}
	if os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], stateTag)
	_ = os.WriteFile(path, buf[:], 0o600)
}
