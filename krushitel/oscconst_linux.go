//go:build linux

package main

import "golang.org/x/sys/unix"

const (
	tcgetattr = unix.TCGETS
	tcsetattr = unix.TCSETS
)
