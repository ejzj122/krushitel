//go:build !windows

package main

// enableVTInput is a no-op on POSIX — terminals deliver ESC sequences natively.
func enableVTInput() {}
