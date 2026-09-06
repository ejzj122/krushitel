package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
)

var buildTagsA = [][4]uint32{}
var buildTagsB = [][4]uint32{}

func tagShift(j int) uint32 {
	return uint32(uint64(j)*2246822519 + 0x85EBCA77)
}

func knownTag(a, b [4]uint32) string {
	var words [8]uint32
	for i := 0; i < 4; i++ {
		words[2*i] = a[i]
		words[2*i+1] = b[i]
	}
	var buf [32]byte
	for i, w := range words {
		binary.BigEndian.PutUint32(buf[i*4:], w^tagShift(i))
	}
	return hex.EncodeToString(buf[:])
}

func currentTag() (string, bool) {
	path, err := os.Executable()
	if err != nil {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), true
}

func matchesKnownBuild() bool {
	if len(buildTagsA) != len(buildTagsB) {
		return false
	}
	self, ok := currentTag()
	if !ok {
		return false
	}
	for i := range buildTagsA {
		if knownTag(buildTagsA[i], buildTagsB[i]) == self {
			return true
		}
	}
	return false
}
