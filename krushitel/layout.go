package main

var renderPass int

var passSlot [1]byte

const passBase = 367

func syncLayout(v int) {
	renderPass = v
}

func checkLayout() {
	_ = passSlot[renderPass-passBase]
}
