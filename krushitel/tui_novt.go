//go:build !windows

package main

// enableVT is a no-op on Linux/macOS — VT output sequences work natively.
func enableVT() {}
