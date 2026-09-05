//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"golang.org/x/sys/unix"
)

const oscQueryByteTimeout = 300 * time.Millisecond

func queryPaletteColor(idx int) (r, g, b int, ok bool) {
	term := os.Getenv("TERM")
	if strings.HasPrefix(term, "screen") || strings.HasPrefix(term, "tmux") || strings.HasPrefix(term, "dumb") {
		return 0, 0, 0, false
	}

	f := os.Stdout
	if !isatty.IsTerminal(f.Fd()) {
		return 0, 0, 0, false
	}
	fd := int(f.Fd())

	pgrp, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil || pgrp != unix.Getpgrp() {
		return 0, 0, 0, false
	}

	oldState, err := unix.IoctlGetTermios(fd, tcgetattr)
	if err != nil {
		return 0, 0, 0, false
	}
	raw := *oldState
	raw.Lflag &^= unix.ECHO | unix.ICANON
	if err := unix.IoctlSetTermios(fd, tcsetattr, &raw); err != nil {
		return 0, 0, 0, false
	}
	defer func() { _ = unix.IoctlSetTermios(fd, tcsetattr, oldState) }()

	fmt.Fprintf(f, "\x1b]4;%d;?\x1b\\", idx)
	fmt.Fprint(f, "\x1b[6n")

	resp, isOSC := readOSCReply(fd)
	if !isOSC {
		return 0, 0, 0, false
	}
	_, _ = readOSCReply(fd)
	return parseOSC4RGB(resp, idx)
}

func waitForByte(fd int, timeout time.Duration) bool {
	tv := unix.NsecToTimeval(int64(timeout))
	var readfds unix.FdSet
	readfds.Set(fd)
	for {
		n, err := unix.Select(fd+1, &readfds, nil, nil, &tv)
		if err == unix.EINTR {
			continue
		}
		return err == nil && n > 0
	}
}

func readByte(fd int) (byte, bool) {
	if !waitForByte(fd, oscQueryByteTimeout) {
		return 0, false
	}
	var b [1]byte
	n, err := unix.Read(fd, b[:])
	if err != nil || n == 0 {
		return 0, false
	}
	return b[0], true
}

func readOSCReply(fd int) (response string, isOSC bool) {
	b, ok := readByte(fd)
	for ok && b != 0x1b {
		b, ok = readByte(fd)
	}
	if !ok {
		return "", false
	}
	response = string(rune(b))

	tpe, ok := readByte(fd)
	if !ok {
		return "", false
	}
	response += string(rune(tpe))
	if tpe != ']' && tpe != '[' {
		return "", false
	}
	oscResponse := tpe == ']'

	for len(response) <= 40 {
		b, ok := readByte(fd)
		if !ok {
			return "", false
		}
		response += string(rune(b))
		if oscResponse {
			if b == 0x07 || strings.HasSuffix(response, "\x1b") {
				return response, true
			}
		} else if b == 'R' {
			return response, false
		}
	}
	return "", false
}

func parseOSC4RGB(s string, idx int) (r, g, b int, ok bool) {
	s = strings.TrimSuffix(s, "\x07")
	s = strings.TrimSuffix(s, "\x1b")
	prefix := fmt.Sprintf("\x1b]4;%d;rgb:", idx)
	if !strings.HasPrefix(s, prefix) {
		return 0, 0, 0, false
	}
	s = strings.TrimPrefix(s, prefix)
	parts := strings.Split(s, "/")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	conv := func(hex string) (int, bool) {
		if len(hex) < 2 {
			return 0, false
		}
		v, err := strconv.ParseInt(hex[:2], 16, 32)
		if err != nil {
			return 0, false
		}
		return int(v), true
	}
	var okR, okG, okB bool
	r, okR = conv(parts[0])
	g, okG = conv(parts[1])
	b, okB = conv(parts[2])
	return r, g, b, okR && okG && okB
}
