//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package main

func queryPaletteColor(idx int) (r, g, b int, ok bool) {
	return 0, 0, 0, false
}
