package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	var target [57]byte
	sha1 := []byte("d1baa8ab45a9c34c1446")
	uuid := []byte("4ba1aced491cf4dd11bd")
	rndb := []byte("ABCDEFGHIJKLMNOPQRSTUVW")
	want := "0300562e474d48b14654493b4442a9f0513d05551bef78419fd28d4c4f4301b134fd53f2b4457640224a7a4ec9505259d08b7406364b520557"
	r1, r2, err := syscall.MustLoadDLL("libhashab.dll").MustFindProc("calcHashAB").Call(
		uintptr(unsafe.Pointer(&target[0])),
		uintptr(unsafe.Pointer(&sha1[0])),
		uintptr(unsafe.Pointer(&uuid[0])),
		uintptr(unsafe.Pointer(&rndb[0])))
	if r2 == 0 {
		println(err.Error())
	} else if r1 != 0 {
		println("error", r1)
	} else {
		got := fmt.Sprintf("%x", target[0:57])
		if want != got {
			println("error", got)
		} else {
			fmt.Println("OK")
		}
	}
}
